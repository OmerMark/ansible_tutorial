import time
import copy
import re
from common.constants import UNDERCLOUD, HOSTS_CONFIG_BEFORE_CHANGES, \
    HOSTS_CONFIG_TMP, HOSTS_CONFIG, HOSTS_CONFIG_THE_LAST_CREATED, CINDER_CONF, \
    HOSTS_CONFIG_FOR_DEBUG
from conf import config
from common.commons import CbisException
from common.constants import StackStates, CBIS_INSTALLER_PATH
from flows.base_deployment import CbisBaseDeployment
from cbis_common.hosts_config_utility import hosts_config_utility
from cbis_common.ceph_configurations import CephConfigurations

SLEEP_TIME_SECONDS = 5
WAIT_INTERVAL_AFTER_OSD_OUT_SECONDS = 2
MAX_TIMES = 20
LOOP_TIMEOUT = 10


class RemoveNode(CbisBaseDeployment):
    nodes_to_remove = []
    ignore_ceph_errors = False
    hosts_utility = None
    is_multiple_pools = False

    def __init__(self, logger):
        super(RemoveNode, self).__init__(logger)

    def set_request(self, request, page_json, hardware=None):
        super(RemoveNode, self).set_request(request, page_json)
        self.nodes_to_remove = \
            self.request['remove_node_main']['remove_node_params']['node_names']
        self.ignore_ceph_errors = \
            self.request['remove_node_main']['remove_node_params'][
                'ignore_ceph_errors']

    def deploy(self):
        self.log.info("**Remove node started for hosts: {}**".format(
            self.nodes_to_remove))

        self.log.info("**Collecting information about the system**")
        self.check_if_tls_enabled()
        self.check_ssh_access(self.nodes_to_remove)
        ceph_exists = self.check_ceph_enabled()

        if ceph_exists:
            osds_to_delete = self.fetch_osd_ids(self.nodes_to_remove)
            self.log.info("Found Ceph nodes to delete: {}".format(
                osds_to_delete.keys()))
            self.log.info("Found OSDs to delete: {}".format(osds_to_delete))

        nova_ids = self.fetch_nova_ids_for_nodes(self.nodes_to_remove)
        self.log.info("Found nova ids to remove: {}".format(nova_ids))

        ironic_ids = self.fetch_ironic_ids(nova_ids)
        ipmis = self.get_ipmi_of_removed_node(nova_ids)
        self.cbis_helper.cmds_run_sync(['scp -o StrictHostKeyChecking=no '
                                        'stack@uc:/home/stack/hosts_config.yaml'
                                        ' {} '
                                       .format(HOSTS_CONFIG_BEFORE_CHANGES)])
        self.hosts_utility = hosts_config_utility(HOSTS_CONFIG_BEFORE_CHANGES)
        self.is_multiple_pools = self.hosts_utility.is_multiple_pools_enabled()
        self.log.info("Found ironic ids to remove: {}".format(ironic_ids))

        self.log.info("**Executing pre-checks**")
        self.check_if_vms_are_running(self.nodes_to_remove)

        # remove Ceph from all nodes with Ceph installed as step 1
        if ceph_exists and osds_to_delete:
            self.log.info("**Executing Ceph checks**")
            self.do_ceph_checks(osds_to_delete, self.ignore_ceph_errors, ipmis)

            for node in osds_to_delete:
                self.log.info("**Marking Ceph OSDs out for {} ({})**".format(
                    node, osds_to_delete[node]))
                self.mark_osds_out(osds_to_delete[node])

                self.wait_for_ceph_health(self.ignore_ceph_errors)

            for node in osds_to_delete:
                self.log.info("**Stopping OSD services for {}**".format(node))
                self.stop_osd_services(node)

                self.log.info("**Removing OSDs for {}**".format(node))
                self.completely_remove_osds(osds_to_delete[node], node, ipmis)

            self.log.info("**Waiting for Ceph health after stopping Ceph "
                          "services and removing OSDs**")
            self.wait_for_ceph_health(self.ignore_ceph_errors)

        # as step 2, remove all nodes from nova and ironic
        # at this point, all nodes don't have Ceph
        self.log.info("**Removing hosts from host aggregates**")
        self.remove_hosts_from_aggregates(self.nodes_to_remove)

        self.log.info("**Disabling compute services**")
        self.disable_compute_services(self.nodes_to_remove)

        self.log.info("**Stack update - removing nodes: {}**".format(nova_ids))
        self.update_stack(nova_ids)
        self.remove_from_hosts_config(ipmis)
        if ceph_exists:
            self.remove_ceph_user_from_nodes(ipmis)
        self.cbis_helper.cmds_run_sync([
            'scp -o StrictHostKeyChecking=no {} stack@uc:{}'
                .format(HOSTS_CONFIG_TMP, HOSTS_CONFIG_THE_LAST_CREATED)])
        self.cbis_helper.ssh_cmds(UNDERCLOUD, ['sudo mv {} /usr/share/cbis'
                                  .format(HOSTS_CONFIG_THE_LAST_CREATED)])

        self.log.info("**Removing compute services**")
        self.remove_nova_compute_services(self.nodes_to_remove)

        self.log.info("**Removing neutron agents**")
        self.remove_neutron_agents(self.nodes_to_remove)

        self.log.info("**Removing ironic instances: {}**".format(ironic_ids))
        self.remove_from_ironic(ironic_ids)

        self.log.info("**Executing post-checks**")
        self.validate_ironic(ironic_ids)
        self.validate_nova_nodes(self.nodes_to_remove)

        self.log.info("**Reconfiguring salt roster**")
        self.reconfigure_salt_roster()

        self.log.info("**Regenerating templates**")
        self.generate_templates()

        self.log.info("**Regenerating /etc/hosts on undercloud**")
        self.regenerate_etc_hosts()
        self.call_ceph_playbook()
        self.log.info("**Removing nodes from Zabbix**")
        self.remove_from_zabbix(self.nodes_to_remove)

        self.log.info("**Remove node finished successfully**")
        self.log.info("**Please backup Undercloud**")

    def call_ceph_playbook(self):
        self.log.info("**Calling Ceph fast-pool playbook**")

        self.cbis_helper.ssh_cmds(UNDERCLOUD,
                                  [
                                      "ansible-playbook /usr/share/cbis/cbis-ansible/post-install/ceph-configure-fast-pool.yml"])

        self.log.info("**Finished running Ceph fast-pool playbook**")

    def check_ceph_enabled(self):
        self.log.info("**Checking if ceph is enabled**")
        user_config_full_path = self.configs.get(CBIS_INSTALLER_PATH) + "/user_config.yaml"
        user_config = self.cbis_helper.get_dict_from_file(user_config_full_path)
        ceph_configurations = CephConfigurations(user_config)
        if ceph_configurations.check_ceph_enabled():
            self.log.info("Ceph is enabled")
            return True
        else:
            self.log.info("Ceph is disabled")
            return False

    def do_ceph_checks(self, osds_to_delete, ignore_errors, ipmis):
        self.log.info("**Checking ceph health**")
        health_ok = self.check_ceph_is_healthy()
        if not health_ok and not ignore_errors:
            raise CbisException("Failed in health_ok check")
        enough_disk_space = self.check_ceph_disk_space(osds_to_delete)
        if not enough_disk_space and not ignore_errors:
            raise CbisException("Failed in enough_disk_space check")

        enough_replicas = self.check_ceph_replicas(osds_to_delete, ipmis)
        if not enough_replicas and not ignore_errors:
            raise CbisException("Failed in enough_replicas check")

        pgs_less_than_max_allowed = self.check_pgs_less_than_max_allowed(
            osds_to_delete)
        if not pgs_less_than_max_allowed and not ignore_errors:
            raise CbisException("Failed in pgs_less_than_max_allowed check")

        if not health_ok or not enough_disk_space or not enough_replicas or \
                not pgs_less_than_max_allowed:
            # if we are here => ignore_errors == True
            self.log.warn(
                "Encountered problems with Ceph (health_ok={}, "
                "enough_disk_space={}, enough_replicas={} "
                "pgs_less_than_max_allowed={})".format(health_ok,
                                                       enough_disk_space, enough_replicas,
                                                       pgs_less_than_max_allowed))
            msg = "User selected to ignore Ceph problems, continuing..."
            self.log.warn(msg)
        else:
            self.log.debug("Ceph check passed successfully, continuing....")

    def check_ceph_disk_space(self, osds_to_delete):
        osd_df = self.cbis_helper.execute_on_active_controller(
            ["sudo ceph osd df"],
            as_json=True)

        self.is_multiple_pools = self.hosts_utility.is_multiple_pools_enabled()

        if not self.is_multiple_pools:
            space_total = osd_df["summary"]["total_kb"]
            space_used = osd_df["summary"]["total_kb_used"]
            osds_to_delete_list = [osd_name for host in osds_to_delete for
                                   osd_name in osds_to_delete[host]]
            self.log.debug("osds_to_delete_list {}".format(osds_to_delete_list))

            return self.calculate_ceph_disk_space(osds_to_delete_list, osd_df,
                                                  space_total, space_used)

        pool_osd_dictionary = self.get_osd_pool_dictionary(osds_to_delete)

        ceph_osd_df_tree = self.cbis_helper.execute_on_active_controller(
            ["sudo ceph osd df tree"], as_json=True)

        for pool_name in pool_osd_dictionary:

            host_ids = [host_id for node in ceph_osd_df_tree["nodes"] if
                        node["name"] == pool_name and node["type"] == "root"
                        for host_id in node["children"]]
            osd_ids = [osd_id for node in ceph_osd_df_tree["nodes"] if
                       node["id"] in host_ids for osd_id in node["children"]]
            osds_to_delete_list = [node['name'] for node in
                                   ceph_osd_df_tree["nodes"]
                                   if node['id'] in osd_ids]

            self.log.info("host_ids {} osds_to_delete_list {}".format(
                host_ids, osds_to_delete_list))

            space_total_pool = sum([pool["kb"] for pool in
                                    ceph_osd_df_tree["nodes"]
                                    if pool["name"] == pool_name and
                                    pool["type"] == "root"])
            space_used_pool = sum([pool["kb_used"] for pool in
                                   ceph_osd_df_tree["nodes"]
                                   if pool["name"] == pool and
                                   pool["type"] == "root"])
            self.log.info("space total pool: {} and the space used pool: {}"
                          " for the pool: {}"
                          .format(space_total_pool, space_used_pool, pool_name))

            if not self.calculate_ceph_disk_space(osds_to_delete_list, osd_df,
                                                  space_total_pool,
                                                  space_used_pool):
                return False
        return True

    def check_pgs_less_than_max_allowed(self, osds_to_delete):
        check_pgs_if_scale_in = self.cbis_helper.ssh_cmds(
            UNDERCLOUD,
            ["/usr/share/cbis/undercloud/tools/update_ceph_pgs.sh -c {}".format(
                ",".join(osds_to_delete))])
        find_allow_sacle_in = re.search(r'"allow_scale_in": (\w+)',
                                        check_pgs_if_scale_in)
        if find_allow_sacle_in:
            res = find_allow_sacle_in.group(1)
            return res.lower() == "true"
        return False

    def get_osd_pool_dictionary(self, osds_to_delete):
        pool_osd_dictionary = {}
        for osds in osds_to_delete.values():
            for osd in osds:
                osd_pool_information = self.cbis_helper.execute_on_active_controller(
                    ["sudo ceph osd find {} ".format(osd)], as_json=True)
                pool_name = osd_pool_information["crush_location"]["root"]
                pool_osd_dictionary.setdefault(pool_name, []).append(osd)
        self.log.info("The pool:osds dictionary is:  {}".format(pool_osd_dictionary))
        return pool_osd_dictionary

    def calculate_ceph_disk_space(self, osds_to_delete_list, osd_df,
                                  space_total, space_used):

        space_to_delete = sum([osd["kb"]
                               for osd in osd_df["nodes"]
                               if osd["name"] in osds_to_delete_list])
        space_used_osds = sum([osd["kb_used"]
                               for osd in osd_df["nodes"]
                               if osd["name"] in osds_to_delete_list])

        self.log.debug("Calculated space to delete = {:0.2f} GB".format(
            space_to_delete / (1024 * 1024)))
        self.log.debug("Total space after deletion = {:0.2f} GB".format(
            (space_total - space_to_delete) / (1024 * 1024)))
        self.log.debug("Maximum capacity after operation = {:0.2f} GB".format(
            (space_total - space_to_delete) * 0.85 / (1024 * 1024)))
        self.log.debug("Space used = {} GB space_used_osds {} GB".format(
            space_used / (1024 * 1024), space_used_osds / (1024 * 1024)))

        return (space_total - space_to_delete) * 0.85 >= (space_used -
                                                          space_used_osds)

    def check_ceph_replicas(self, osds_to_delete, ipmis=None):
        osd_dump = self.cbis_helper.execute_on_active_controller(
            ["sudo ceph osd dump"], as_json=True)
        if not self.is_multiple_pools:
            nodes_to_delete_cnt = len(osds_to_delete.keys())
            max_pool_size_common = max(map(
                lambda pool: pool["size"], [pool_ for pool_ in osd_dump["pools"]
                                            if pool_["pool_name"] != "volumes-fast"]))
            ceph_nodes = self.cbis_helper.execute_on_active_controller(
                ["sudo ceph node ls osd"], as_json=True)
            all_nodes_cnt_common = len([node_name for node_name in
                                        ceph_nodes.keys() if not
                                        node_name.startswith("fast-")])
            replica_not_fail_common, at_least_one_osd_common = \
                self.calculate_ceph_replicas(
                    max_pool_size_common, all_nodes_cnt_common, nodes_to_delete_cnt)

            return replica_not_fail_common and at_least_one_osd_common

        self.log.info("Check ceph replica when multiple pools enabled")
        counter_multiple_pools = {}
        ceph_osd_df_tree = self.cbis_helper.execute_on_active_controller(
            ["sudo ceph osd df tree"], as_json=True)
        for ipmi in ipmis:
            pool_names = self.hosts_utility.get_pool_names(ipmi)
            for pool in pool_names:
                if pool in counter_multiple_pools:
                    counter_multiple_pools[pool] = \
                        counter_multiple_pools[pool] + 1
                else:
                    counter_multiple_pools[pool] = 1
        self.log.info("The deleted pools are: {}".format(
            counter_multiple_pools.keys()))
        at_least_one_osd = False
        for pool_name in counter_multiple_pools.keys():
            all_nodes_pool_cnt = sum([len(pool["children"])
                                      for pool in ceph_osd_df_tree["nodes"]
                                      if pool["name"] == pool_name and
                                      pool["type"] == "root"])

            pool_size = max([pool["size"]
                             for pool in osd_dump["pools"]
                             if pool["pool_name"] == pool_name])
            self.log.info("The number of nodes which contribute to "
                          "pool: {} is: {}".format(pool_name, all_nodes_pool_cnt
                                                   ))
            replica_not_fail, at_least_one_osd_for_pool = \
                self.calculate_ceph_replicas(pool_size, all_nodes_pool_cnt,
                                             counter_multiple_pools[pool_name])
            self.log.debug("pool_name {} replica_not_fail {} "
                           "at_least_one_osd_for_pool {}".format(pool_name,
                                                                 replica_not_fail, at_least_one_osd_for_pool))

            if not replica_not_fail:
                return False
            if at_least_one_osd_for_pool:
                at_least_one_osd = True
        return at_least_one_osd

    def calculate_ceph_replicas(self, max_pool_size,
                                all_nodes_cnt, nodes_to_delete_cnt):
        self.log.debug(
            "Max pool size: {}, number of nodes after deletion: {}".format(
                max_pool_size, all_nodes_cnt - nodes_to_delete_cnt))
        at_least_one_osd = all_nodes_cnt - nodes_to_delete_cnt != 0
        replica_not_fail = True
        if at_least_one_osd:
            replica_not_fail = \
                all_nodes_cnt - nodes_to_delete_cnt >= max_pool_size
        return replica_not_fail, at_least_one_osd

    def get_ipmi_of_removed_node(self, nova_instance_ids):
        ipmis = []
        ironic_nodes = self.cbis_helper.ssh_cmds_json(
            UNDERCLOUD,
            ["openstack baremetal node list"]
        )
        for nova_instance_id in nova_instance_ids:
            self.log.debug(
                "Following ironic instances will be removed: {}".format(
                    nova_instance_ids))
            server_id = next(node["Name"] for node in ironic_nodes
                             if node["Instance UUID"] == nova_instance_id)
            cmd = "openstack baremetal node show " + server_id
            node_info = self.cbis_helper.ssh_cmds_json(UNDERCLOUD, [cmd])
            ipmi = node_info["driver_info"]["ipmi_address"]
            ipmis.append(ipmi)

        self.log.debug("The IPMIs of the removed nodes are: {}".format(ipmis))
        return ipmis

    def check_if_vms_are_running(self, nodes):
        vms_on_nodes_to_be_deleted = filter(
            lambda vm: vm["Host"] in self.get_hostnames_for_nova_nodes(nodes),
            self.fetch_overcloud_server_list())

        if vms_on_nodes_to_be_deleted:
            msg = "Found VMs running on nodes to be removed. Following VMs " \
                  "need to be evacuated/deleted before continuing: " \
                  "{}".format(vms_on_nodes_to_be_deleted)
            self.log.error(msg)
            raise CbisException(msg)

    def mark_osds_out(self, osd_ids):
        ceph_status = self.cbis_helper.execute_on_active_controller(
            ["sudo ceph -s"], as_json=True)
        is_norebalance = "norebalance flag(s) set" in str(ceph_status)
        if not is_norebalance:
            self.log.debug("Setting no rebalance and  start getting out OSDs")
            self.cbis_helper.execute_on_active_controller(
                ["ceph osd set norebalance "])
        else:
            self.log.debug("Start getting out OSDs. (norebalance is already set)")
        for osd in osd_ids:
            self.cbis_helper.execute_on_active_controller(
                ["sudo ceph osd out " + osd])
            time.sleep(WAIT_INTERVAL_AFTER_OSD_OUT_SECONDS)

        if not is_norebalance:
            self.cbis_helper.execute_on_active_controller(
                ["ceph osd unset norebalance "])

        self.log.info("After marking OSDs out")

    def fetch_osd_ids(self, nodes):
        node_ls_osd = self.cbis_helper.execute_on_active_controller(
            ["sudo ceph node ls osd"], as_json=True)

        osd_ids = {}
        for node in nodes:
            osds_for_node = []
            for ceph_host in node_ls_osd:
                if ceph_host.endswith(node):
                    osds_for_node.extend(
                        map(lambda osd_num: "osd." + str(osd_num),
                            node_ls_osd[ceph_host]))
            if osds_for_node:
                osd_ids[node] = osds_for_node

        return osd_ids

    def stop_osd_services(self, node):
        try:
            # we need to go through all services separately because of some bug
            # in ceph-osd.target
            services_to_stop = self.cbis_helper.execute_on_host(
                node, ["systemctl | "
                       "grep ceph-osd@.*.service | "
                       "grep -v ceph-osd.target | "
                       "awk '{print $1}' | "
                       "xargs echo"]).split()
            for service in services_to_stop:
                self.cbis_helper.execute_on_host(
                    node, ["sudo systemctl stop {}".format(service)])

            time_out = time.time() + config.SYSTEMCTL_TIMEOUT
            is_active = True
            while is_active and time.time() < time_out:
                is_active = int(self.cbis_helper.execute_on_host(
                    node,
                    ["sudo docker ps | grep ceph-osd | wc -l"])) != 0
                time.sleep(LOOP_TIMEOUT)
            if is_active:
                self.log.warn("Ceph services still running after timeout")
        except Exception as e:
            self.log.warn("Can't stop Ceph service on the node {}: {}".format(
                node, e))

    def remove_from_hosts_config(self, ipmis):
        self.log.debug("copy the hosts_config.yaml from UC")
        self.cbis_helper.cmds_run_sync([
            'scp -o StrictHostKeyChecking=no stack@uc:/'
            'home/stack/hosts_config.yaml {} '.format(HOSTS_CONFIG_TMP)])
        hosts_config_dictionary = self.cbis_helper.get_dict_from_file(
            HOSTS_CONFIG_TMP)
        tmp_json = copy.deepcopy(hosts_config_dictionary)
        for host_group in tmp_json['host_groups']:
            hostgroup_index = hosts_config_dictionary[
                'host_groups'].index(host_group)
            if 'pm_addr' in host_group and host_group['pm_addr'] is not None:
                for ip in host_group['pm_addr']:
                    for ipmi in ipmis:
                        if ip == ipmi:
                            if len(hosts_config_dictionary['host_groups'][
                                       hostgroup_index]['pm_addr']) == 1:
                                self.log.debug(
                                    "remove the hosts group section: {} "
                                    "from hosts_config".format(
                                        host_group['host_group']))
                                del hosts_config_dictionary['host_groups'][
                                    hostgroup_index]
                            else:
                                self.log.debug(
                                    'remove the ip: {} from hosts_config,'
                                    ' host_group index is: {}'
                                        .format(ipmi, hostgroup_index))
                                hosts_config_dictionary['host_groups'][
                                    hostgroup_index]['pm_addr'].remove(ipmi)
        self.log.debug("hosts_config dict after changes: {}".format(
            hosts_config_dictionary))
        self.cbis_helper.write_dict_to_file(HOSTS_CONFIG_TMP,
                                            hosts_config_dictionary)
        self.cbis_helper.cmds_run_sync([
            'scp -o StrictHostKeyChecking=no {} stack@uc:{}'
                .format(HOSTS_CONFIG_TMP, HOSTS_CONFIG)])

    def completely_remove_osds(self, osd_ids, node, ipmis):
        self.log.warn("If this operation fails you may need to "
                      "power off the node of which the"
                      " OSD was associated to by running:\n "
                      " baremetal node power off <server-name> \n"
                      "and baremetal node maintenance set <server-name")
        for osd in osd_ids:
            self.cbis_helper.execute_on_active_controller(
                ["sudo ceph osd crush remove {}".format(osd),
                 "sudo ceph auth del {}".format(osd),
                 "sudo ceph osd rm {}".format(osd)]
            )

        # TODO: Noam Sitton - read the field as yaml and search for the value
        fast_pool_in_user_config = self.cbis_helper.ssh_cmds(
            UNDERCLOUD,
            ["grep enable_fast_pool /home/stack/templates/user_config.yaml"
             " | awk '{ print $2 }'"]).strip() == "true"

        if self.is_multiple_pools:
            for ipmi in ipmis:
                self.log.info("remove multiple pool hostname from crush map")
                pool_list = self.hosts_utility.get_pool_names(ipmi)
                if pool_list:
                    for pool in pool_list:
                        cmd = '"sudo ceph osd tree | grep -w ' + "'host {}-{}'" \
                                                                 " && sudo ceph osd crush remove {}-{} || echo " \
                                                                 "'Skipping unexisting node" \
                                                                 " entry'".format \
                            (pool, node.lower(), pool, node.lower()) + '"'
                        self.cbis_helper.execute_on_active_controller([cmd])
                        cmd = '"sudo ceph osd tree | grep -w ' + "'host {}'" \
                                                                 " && sudo ceph osd crush remove {} || echo " \
                                                                 "'Skipping unexisting node" \
                                                                 " entry'".format(node.lower(), node.lower()) + '"'
                        self.cbis_helper.execute_on_active_controller([cmd])

                delete_pool_from_crush_map = self.hosts_utility. \
                    get_deleted_pools(ipmis)
                for pool in delete_pool_from_crush_map:
                    self.cbis_helper.execute_on_active_controller(
                        ["sudo ceph osd pool rm {0} {0} "
                         "--yes-i-really-really-mean-it".format(pool),
                         "sudo ceph osd crush rule rm"
                         " {}_replicated_ruleset".format(pool),
                         "sudo ceph osd crush remove {}".format(pool)])
        elif fast_pool_in_user_config:
            self.log.info("remove fast pool hostname from crush map")
            self.cbis_helper.execute_on_active_controller(
                ["sudo ceph osd crush remove common-{}".format(node.lower()),
                 "sudo ceph osd crush remove fast-{}".format(node.lower())])
        else:
            self.log.info("remove hostname from crush map")
            self.cbis_helper.execute_on_active_controller(
                ["sudo ceph osd crush remove {}".format(node.lower())])

    def remove_hosts_from_aggregates(self, nodes):
        for aggregate in self.fetch_overcloud_aggregates():
            aggregate_details = self.cbis_helper.execute_on_overcloud(
                ["openstack aggregate show {}".format(aggregate["ID"])],
                as_json=True)

            hosts_to_remove_from_aggregate = filter(
                lambda hostname: hostname in aggregate_details["hosts"],
                self.get_hostnames_for_nova_nodes(nodes))

            for host in hosts_to_remove_from_aggregate:
                self.cbis_helper.execute_on_overcloud(
                    ["openstack aggregate remove host {} {}".format(
                        aggregate["ID"], host)])

    def disable_compute_services(self, nodes):
        services_to_disable = filter(
            lambda serv:
            serv["Host"] in self.get_hostnames_for_nova_nodes(nodes),
            self.fetch_overcloud_compute_services())

        for service in services_to_disable:
            self.cbis_helper.execute_on_overcloud(
                ["openstack compute service set --disable {} {}".format(
                    service["Host"], service["Binary"])])

    def update_stack(self, nova_instance_ids):
        cmd = "openstack cbis node remove {}".format(str(" ".join(nova_instance_ids)))

        self.cbis_helper.ssh_cmds(UNDERCLOUD, [cmd])
        self.validate_heat_output([StackStates.UPDATE_COMPLETE],
                                  wait_for_progress=False)

        non_deleted_nodes = nova_instance_ids
        counter = 0
        while non_deleted_nodes and counter < MAX_TIMES:
            self.log.info("Waiting for nova instances {} to be removed".format(
                nova_instance_ids))
            ironic_nodes = self.fetch_ironic_nodes()
            non_deleted_nodes = filter(
                lambda node: node["Instance UUID"] in nova_instance_ids,
                ironic_nodes)

            time.sleep(SLEEP_TIME_SECONDS)
            counter += 1

        if counter >= MAX_TIMES:
            msg = "Some of the nova instances are not removed ({}), aborting " \
                  "operation.".format(nova_instance_ids)
            self.log.error(msg)
            raise CbisException(msg)

    def remove_from_ironic(self, ironic_ids):
        cmd = []
        for id in ironic_ids:
            cmd.append("openstack baremetal node maintenance set " + id)
        cmd.append("openstack baremetal node delete {}".format(" ".join(ironic_ids)))
        self.cbis_helper.ssh_cmds(
            UNDERCLOUD,
            cmd)

    def remove_nova_compute_services(self, nodes):
        hostnames = self.get_hostnames_for_nova_nodes(nodes)

        # remove services for all nodes
        services_to_remove = filter(
            lambda service: service["Host"] in hostnames,
            self.fetch_overcloud_compute_services())
        service_ids = map(lambda service: service["ID"], services_to_remove)

        # Making sure there are services on the removed node/s (for storage
        # nodes there are no services)
        if len(service_ids) > 0:
            self.cbis_helper.execute_on_overcloud(
                ["openstack compute service delete {}".format(
                    " ".join(map(str, service_ids)))])

            # verifying services were removed
            services_not_removed = filter(
                lambda service: service["Host"] in hostnames,
                self.fetch_overcloud_compute_services())

            if services_not_removed:
                msg = "Following services were not removed from nova service " \
                      "list: {}".format(services_not_removed)
                self.log.error(msg)
                raise CbisException(msg)

    def remove_neutron_agents(self, nodes):
        hostnames = self.get_hostnames_for_nova_nodes(nodes)

        # remove agents for all nodes
        agents_to_remove = filter(lambda agent: agent["Host"] in hostnames,
                                  self.fetch_overcloud_network_agents())
        agent_ids = map(lambda agent: agent["ID"], agents_to_remove)

        # Making sure there are network agents on the removed node/s (for
        # storage nodes there are no agents)
        if len(agent_ids) > 0:
            self.cbis_helper.execute_on_overcloud(
                ["openstack network agent delete {}".format(" ".join(agent_ids))])

            # verifying agents were removed
            agents_not_removed = filter(lambda agent: agent["Host"] in hostnames,
                                        self.fetch_overcloud_network_agents())
            if agents_not_removed:
                msg = "Following neutron agents were not removed: {}".format(
                    agents_not_removed)
                self.log.error(msg)
                raise CbisException(msg)

    def reconfigure_salt_roster(self):
        self.cbis_helper.ssh_cmds(
            UNDERCLOUD,
            ["/bin/bash "
             "/usr/share/cbis/undercloud/tools/configure_salt_build_roster.sh"])

    def validate_ironic(self, ironic_ids):
        non_deleted_nodes = filter(lambda node: node["UUID"] in ironic_ids,
                                   self.fetch_ironic_nodes())

        if non_deleted_nodes:
            msg = "Some of ironic instances were not removed successfully: " \
                  "{}".format(non_deleted_nodes)
            self.log.error(msg)
            raise CbisException(msg)

    def validate_nova_nodes(self, nodes):
        non_deleted_instances = filter(
            lambda instance: instance["Name"] in nodes,
            self.fetch_nova_server_list())

        if non_deleted_instances:
            msg = "Some nova instances were not removed successfully: " \
                  "{}".format(non_deleted_instances)
            self.log.error(msg)
            raise CbisException(msg)

    def fetch_nova_ids_for_nodes(self, nodes):
        return [nova_instance["ID"]
                for nova_instance in self.fetch_nova_server_list()
                if nova_instance["Name"] in nodes]

    def fetch_ironic_ids(self, nova_ids):
        return [node["UUID"]
                for node in self.fetch_ironic_nodes()
                if node["Instance UUID"] in nova_ids]

    def fetch_nova_server_list(self):
        return self.cbis_helper.ssh_cmds_json(UNDERCLOUD,
                                              ["openstack server list"])

    def fetch_ironic_nodes(self):
        return self.cbis_helper.ssh_cmds_json(UNDERCLOUD,
                                              ["openstack baremetal node list"])

    def fetch_overcloud_compute_services(self):
        return self.cbis_helper.execute_on_overcloud(
            ["openstack compute service list"],
            as_json=True)

    def fetch_overcloud_server_list(self):
        return self.cbis_helper.execute_on_overcloud(
            ["openstack server list --all --long"],
            as_json=True)

    def fetch_overcloud_aggregates(self):
        return self.cbis_helper.execute_on_overcloud(
            ["openstack aggregate list"],
            as_json=True)

    def fetch_overcloud_network_agents(self):
        return self.cbis_helper.execute_on_overcloud(
            ["openstack network agent list"],
            as_json=True)

    def remove_ceph_user_from_nodes(self, ipmis):
        if self.is_multiple_pools:
            self.log.info("Multiple pools enabled. Check and remove ceph user ")
            delete_ceph_user_pool = self.hosts_utility.get_deleted_pools(ipmis)
            if delete_ceph_user_pool:
                for pool in delete_ceph_user_pool:
                    self.unset_uuid_secret_active_controllers(pool)
                    self.cbis_helper.execute_on_active_controller(
                        ["sudo ceph auth del client.{}".format(pool)])
                    self.cbis_helper.execute_on_overcloud(
                        ["cinder type-delete tripleo-ceph-{}".format(pool)])
                    self.cbis_helper.execute_on_all_active_controllers(
                        ["sudo crudini --del {} "
                         "'tripleo-ceph-{}'".format(CINDER_CONF, pool),
                         "sudo rm -f /etc/ceph/ceph.client.{}.keyring ".format
                         (pool), "sudo rm -f /etc/nova/secret_{}.xml".format
                         (pool)])
                    self.log.info("Delete the ceph user of the: {} ".
                                  format(pool))
                enable_backends_list = self.cbis_helper.execute_on_active_controller(
                    ["sudo crudini --get {} "
                     "'DEFAULT' 'enabled_backends'".format(CINDER_CONF)]).split(",")
                enable_backends_list = map(str.strip, enable_backends_list)
                hosts_utility_new = \
                    hosts_config_utility(src_hosts=HOSTS_CONFIG_TMP)
                list_pool_for_enabled_backend = hosts_utility_new. \
                    get_all_pool_names()
                prefix_of_enabled_backend = "tripleo-ceph-"
                str_vm_pool = " "
                if list_pool_for_enabled_backend:
                    str_vm_pool = list_pool_for_enabled_backend[0]
                for pool in delete_ceph_user_pool:
                    if "tripleo-ceph-{}".format(pool) in enable_backends_list:
                        enable_backends_list.remove("tripleo-ceph-{}".format(pool))
                str_pool_for_enabled_backend = enable_backends_list[0]
                for item in enable_backends_list[1:]:
                    str_pool_for_enabled_backend = \
                        str_pool_for_enabled_backend + "," + item

                self.log.info("Edit the cinder.conf file")
                self.cbis_helper.execute_on_all_active_controllers(
                    ['sudo crudini --set {} "DEFAULT" '
                     '"enabled_backends" "{}"'.format
                     (CINDER_CONF, str_pool_for_enabled_backend),
                     'sudo crudini --set {0} "DEFAULT" "default_volume_type"'
                     ' "{1}{2}"'.format(CINDER_CONF, prefix_of_enabled_backend,
                                        str_vm_pool)])
                self.log.info("Restart openstack cinder services")
                self.cbis_helper.execute_on_active_controller(
                    ['sudo pcs resource restart openstack-cinder-volume',
                     'sudo docker restart cinder_api',
                     'sudo docker restart cinder_scheduler'])

    def unset_uuid_secret_active_controllers(self, pool):
        self.log.info("Executing unset uuid command on all active controllers")
        all_active_controllers = self.cbis_helper.find_all_active_controllers()
        for controller in all_active_controllers:
            uuid = self.cbis_helper.execute_on_host(
                controller, ['sudo cat /etc/nova/secret_{}.xml '
                             '| grep "uuid" | cut -d ">" -f2 '
                             '| cut -d "<" -f1'.format(pool)])
            self.cbis_helper.execute_on_host(
                controller, ['sudo virsh secret-undefine {}'.format(uuid)])

    @staticmethod
    def get_hostnames_for_nova_nodes(nodes):
        return map(lambda node: node.lower() + ".localdomain", nodes)

    def regenerate_etc_hosts(self):
        self.cbis_helper.ssh_cmds(UNDERCLOUD, [
            "sudo /usr/share/cbis/cbis-ansible/tools/setup-ansible.sh",
            "ansible-playbook /usr/share/cbis/cbis-ansible/post-install/configure-etc-hosts.yml"
        ])

    def remove_from_zabbix(self, nodes_to_remove):
        for node in nodes_to_remove:
            self.cbis_helper.ssh_cmds(UNDERCLOUD, [
                "/usr/share/cbis/undercloud/tools/zabbix/zabbix_delete_host.py {}".format(node)])
