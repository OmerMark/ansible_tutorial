#!/bin/bash
# Please do not change this file directly since it is managed by Ansible and will be overwritten

DOCKER_ENV=""

#############
# FUNCTIONS #
#############
function expose_partitions () {
DOCKER_ENV=$(docker run --rm --name expose_partitions_${1} --privileged=true -v /dev/:/dev/ -v /etc/ceph:/etc/ceph -e CLUSTER=ceph -e OSD_DEVICE=/dev/${1} 172.31.0.1:8787/ceph/daemon:tag-build-master-luminous-centos-7 disk_list)
  docker rm -f expose_partitions_${1}
}
expose_partitions "$1"

function get_hostname {
local device=${1}
local found=0
for osd in `crudini --get /etc/ceph/ceph.conf | grep "^osd.[0-9]\+$"`; do
    local osd_device=`crudini --get /etc/ceph/ceph.conf ${osd} OSD_DEVICE 2> /dev/null`
    if $(echo "${osd_device}" | grep -q "^${device}[0-9]*"); then
        local host=`crudini --get /etc/ceph/ceph.conf ${osd} HOSTNAME 2> /dev/null`
        local found=1
        break
    fi
done
if [ ! -z "${host}" ] && [ ${found} -eq 1 ]; then
    echo "${host}"
else
    echo "$(hostname -s)"
fi
}

hostname=$(get_hostname ${1})
cpus=$(echo -n $(cat /usr/share/cbis/data/cbis.cpu_isolation | grep ^host_cpus: | cut -d ':' -f2) )
# Creating an empty log file for the OSD
touch /var/log/ceph/ceph_osd-${1}.log
chown ceph. /var/log/ceph/ceph_osd-${1}.log
chmod 755 /var/log/ceph/ceph_osd-${1}.log



########
# MAIN #
########

/usr/bin/docker run \
  -h ${hostname} \
  --rm \
  --net=host \
  --privileged=true \
  --pid=host \
  --memory=5g \
  --cpu-quota=100000 \
  --cpuset-cpus="${cpus}" \
  -v /dev:/dev \
  -v /etc/localtime:/etc/localtime:ro \
  -v /var/lib/ceph:/var/lib/ceph \
  -v /etc/ceph:/etc/ceph \
  -v /var/log/ceph/ceph_osd-${1}.log:/var/log/ceph/ceph.log:z \
  $DOCKER_ENV \
  -e OSD_BLUESTORE=1 \
  -e OSD_DMCRYPT=0 \
  -e CLUSTER=ceph \
  -e OSD_DEVICE=/dev/${1} \
  -e CEPH_OSD_ON_ROOT=/dev/${1} \
  -e CEPH_DAEMON=OSD_CEPH_DISK_ACTIVATE \
   \
  --name=ceph-osd-$(hostname -s)-${1} \
  172.31.0.1:8787/ceph/daemon:tag-build-master-luminous-centos-7
