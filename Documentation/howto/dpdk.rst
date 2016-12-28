..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============================
Using Open vSwitch with DPDK
============================

This document describes how to use Open vSwitch with DPDK datapath.

.. important::

   Using the DPDK datapath requires building OVS with DPDK support. Refer to
   :doc:`/intro/install/dpdk` for more information.

Ports and Bridges
-----------------

ovs-vsctl can be used to set up bridges and other Open vSwitch features.
Bridges should be created with a ``datapath_type=netdev``::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

ovs-vsctl can also be used to add DPDK devices. OVS expects DPDK device names
to start with ``dpdk`` and end with a portid. ovs-vswitchd should print the
number of dpdk devices found in the log file::

    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
    $ ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk

After the DPDK ports get added to switch, a polling thread continuously polls
DPDK devices and consumes 100% of the core, as can be checked from ``top`` and
``ps`` commands::

    $ top -H
    $ ps -eLo pid,psr,comm | grep pmd

Creating bonds of DPDK interfaces is slightly different to creating bonds of
system interfaces. For DPDK, the interface type must be explicitly set. For
example::

    $ ovs-vsctl add-bond br0 dpdkbond dpdk0 dpdk1 \
        -- set Interface dpdk0 type=dpdk \
        -- set Interface dpdk1 type=dpdk

To stop ovs-vswitchd & delete bridge, run::

    $ ovs-appctl -t ovs-vswitchd exit
    $ ovs-appctl -t ovsdb-server exit
    $ ovs-vsctl del-br br0

PMD Thread Statistics
---------------------

To show current stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

To clear previous stats::

    $ ovs-appctl dpif-netdev/pmd-stats-clear

Port/RXQ Assigment to PMD Threads
---------------------------------

To show port/rxq assignment::

    $ ovs-appctl dpif-netdev/pmd-rxq-show

To change default rxq assignment to pmd threads, rxqs may be manually pinned to
desired cores using::

    $ ovs-vsctl set Interface <iface> \
        other_config:pmd-rxq-affinity=<rxq-affinity-list>

where:

- ``<rxq-affinity-list>`` is a CSV list of ``<queue-id>:<core-id>`` values

For example::

    $ ovs-vsctl set interface dpdk0 options:n_rxq=4 \
        other_config:pmd-rxq-affinity="0:3,1:7,3:8"

This will ensure:

- Queue #0 pinned to core 3
- Queue #1 pinned to core 7
- Queue #2 not pinned
- Queue #3 pinned to core 8

After that PMD threads on cores where RX queues was pinned will become
``isolated``. This means that this thread will poll only pinned RX queues.

.. warning::
  If there are no ``non-isolated`` PMD threads, ``non-pinned`` RX queues will
  not be polled. Also, if provided ``core_id`` is not available (ex. this
  ``core_id`` not in ``pmd-cpu-mask``), RX queue will not be polled by any PMD
  thread.

QoS
---

Assuming you have a vhost-user port transmitting traffic consisting of packets
of size 64 bytes, the following command would limit the egress transmission
rate of the port to ~1,000,000 packets per second::

    $ ovs-vsctl set port vhost-user0 qos=@newqos -- \
        --id=@newqos create qos type=egress-policer other-config:cir=46000000 \
        other-config:cbs=2048`

To examine the QoS configuration of the port, run::

    $ ovs-appctl -t ovs-vswitchd qos/show vhost-user0

To clear the QoS configuration from the port and ovsdb, run::

    $ ovs-vsctl destroy QoS vhost-user0 -- clear Port vhost-user0 qos

Refer to vswitch.xml for more details on egress-policer.

Rate Limiting
--------------

Here is an example on Ingress Policing usage. Assuming you have a vhost-user
port receiving traffic consisting of packets of size 64 bytes, the following
command would limit the reception rate of the port to ~1,000,000 packets per
second::

    $ ovs-vsctl set interface vhost-user0 ingress_policing_rate=368000 \
        ingress_policing_burst=1000`

To examine the ingress policer configuration of the port::

    $ ovs-vsctl list interface vhost-user0

To clear the ingress policer configuration from the port::

    $ ovs-vsctl set interface vhost-user0 ingress_policing_rate=0

Refer to vswitch.xml for more details on ingress-policer.

Flow Control
------------

Flow control can be enabled only on DPDK physical ports. To enable flow control
support at tx side while adding a port, run::

    $ ovs-vsctl add-port br0 dpdk0 -- \
        set Interface dpdk0 type=dpdk options:tx-flow-ctrl=true

Similarly, to enable rx flow control, run::

    $ ovs-vsctl add-port br0 dpdk0 -- \
        set Interface dpdk0 type=dpdk options:rx-flow-ctrl=true

To enable flow control auto-negotiation, run::

    $ ovs-vsctl add-port br0 dpdk0 -- \
        set Interface dpdk0 type=dpdk options:flow-ctrl-autoneg=true

To turn ON the tx flow control at run time for an existing port, run::

    $ ovs-vsctl set Interface dpdk0 options:tx-flow-ctrl=true

The flow control parameters can be turned off by setting ``false`` to the
respective parameter. To disable the flow control at tx side, run::

    $ ovs-vsctl set Interface dpdk0 options:tx-flow-ctrl=false

pdump
-----

pdump allows you to listen on DPDK ports and view the traffic that is passing
on them. To use this utility, one must have libpcap installed on the system.
Furthermore, DPDK must be built with ``CONFIG_RTE_LIBRTE_PDUMP=y`` and
``CONFIG_RTE_LIBRTE_PMD_PCAP=y``.

.. warning::
  A performance decrease is expected when using a monitoring application like
  the DPDK pdump app.

To use pdump, simply launch OVS as usual, then navigate to the ``app/pdump``
directory in DPDK, ``make`` the application and run like so::

    $ sudo ./build/app/dpdk-pdump -- \
        --pdump port=0,queue=0,rx-dev=/tmp/pkts.pcap \
        --server-socket-path=/usr/local/var/run/openvswitch

The above command captures traffic received on queue 0 of port 0 and stores it
in ``/tmp/pkts.pcap``. Other combinations of port numbers, queues numbers and
pcap locations are of course also available to use. For example, to capture all
packets that traverse port 0 in a single pcap file::

    $ sudo ./build/app/dpdk-pdump -- \
        --pdump 'port=0,queue=*,rx-dev=/tmp/pkts.pcap,tx-dev=/tmp/pkts.pcap' \
        --server-socket-path=/usr/local/var/run/openvswitch

``server-socket-path`` must be set to the value of ``ovs_rundir()`` which
typically resolves to ``/usr/local/var/run/openvswitch``.

Many tools are available to view the contents of the pcap file. Once example is
tcpdump. Issue the following command to view the contents of ``pkts.pcap``::

    $ tcpdump -r pkts.pcap

More information on the pdump app and its usage can be found in the `DPDK docs
<http://dpdk.org/doc/guides/tools/pdump.html>`__.

Jumbo Frames
------------

By default, DPDK ports are configured with standard Ethernet MTU (1500B). To
enable Jumbo Frames support for a DPDK port, change the Interface's
``mtu_request`` attribute to a sufficiently large value. For example, to add a
DPDK Phy port with MTU of 9000::

    $ ovs-vsctl add-port br0 dpdk0 \
      -- set Interface dpdk0 type=dpdk \
      -- set Interface dpdk0 mtu_request=9000`

Similarly, to change the MTU of an existing port to 6200::

    $ ovs-vsctl set Interface dpdk0 mtu_request=6200

Some additional configuration is needed to take advantage of jumbo frames with
vHost ports:

1. *mergeable buffers* must be enabled for vHost ports, as demonstrated in the
   QEMU command line snippet below::

       -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
       -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=on

2. Where virtio devices are bound to the Linux kernel driver in a guest
   environment (i.e. interfaces are not bound to an in-guest DPDK driver), the
   MTU of those logical network interfaces must also be increased to a
   sufficiently large value. This avoids segmentation of Jumbo Frames received
   in the guest. Note that 'MTU' refers to the length of the IP packet only,
   and not that of the entire frame.

   To calculate the exact MTU of a standard IPv4 frame, subtract the L2 header
   and CRC lengths (i.e. 18B) from the max supported frame size.  So, to set
   the MTU for a 9018B Jumbo Frame::

       $ ifconfig eth1 mtu 9000

When Jumbo Frames are enabled, the size of a DPDK port's mbuf segments are
increased, such that a full Jumbo Frame of a specific size may be accommodated
within a single mbuf segment.

Jumbo frame support has been validated against 9728B frames, which is the
largest frame size supported by Fortville NIC using the DPDK i40e driver, but
larger frames and other DPDK NIC drivers may be supported. These cases are
common for use cases involving East-West traffic only.

Rx Checksum Offload
-------------------

By default, DPDK physical ports are enabled with Rx checksum offload. Rx
checksum offload can be configured on a DPDK physical port either when adding
or at run time.

To disable Rx checksum offload when adding a DPDK port dpdk0::

    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk \
      options:rx-checksum-offload=false

Similarly to disable the Rx checksum offloading on a existing DPDK port dpdk0::

    $ ovs-vsctl set Interface dpdk0 type=dpdk options:rx-checksum-offload=false

Rx checksum offload can offer performance improvement only for tunneling
traffic in OVS-DPDK because the checksum validation of tunnel packets is
offloaded to the NIC. Also enabling Rx checksum may slightly reduce the
performance of non-tunnel traffic, specifically for smaller size packet.
DPDK vectorization is disabled when checksum offloading is configured on DPDK
physical ports which in turn effects the non-tunnel traffic performance.
So it is advised to turn off the Rx checksum offload for non-tunnel traffic use
cases to achieve the best performance.

.. _dpdk-ovs-in-guest:

OVS with DPDK Inside VMs
------------------------

Additional configuration is required if you want to run ovs-vswitchd with DPDK
backend inside a QEMU virtual machine. ovs-vswitchd creates separate DPDK TX
queues for each CPU core available. This operation fails inside QEMU virtual
machine because, by default, VirtIO NIC provided to the guest is configured to
support only single TX queue and single RX queue. To change this behavior, you
need to turn on ``mq`` (multiqueue) property of all ``virtio-net-pci`` devices
emulated by QEMU and used by DPDK.  You may do it manually (by changing QEMU
command line) or, if you use Libvirt, by adding the following string to
``<interface>`` sections of all network devices used by DPDK::

    <driver name='vhost' queues='N'/>

where:

``N``
  determines how many queues can be used by the guest.

This requires QEMU >= 2.2.

.. _dpdk-phy-phy:

PHY-PHY
-------

Add a userspace bridge and two ``dpdk`` (PHY) ports::

    # Add userspace bridge
    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

    # Add two dpdk ports
    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
    $ ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk

Add test flows to forward packets betwen DPDK port 0 and port 1::

    # Clear current flows
    $ ovs-ofctl del-flows br0

    # Add flows between port 1 (dpdk0) to port 2 (dpdk1)
    $ ovs-ofctl add-flow br0 in_port=1,action=output:2
    $ ovs-ofctl add-flow br0 in_port=2,action=output:1

Transmit traffic into either port. You should see it returned via the other.

.. _dpdk-vhost-loopback:

PHY-VM-PHY (vHost Loopback)
---------------------------

Add a userspace bridge, two ``dpdk`` (PHY) ports, and two ``dpdkvhostuser``
ports::

    # Add userspace bridge
    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

    # Add two dpdk ports
    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
    $ ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk

    # Add two dpdkvhostuser ports
    $ ovs-vsctl add-port br0 dpdkvhostuser0 \
        -- set Interface dpdkvhostuser0 type=dpdkvhostuser
    $ ovs-vsctl add-port br0 dpdkvhostuser1 \
        -- set Interface dpdkvhostuser1 type=dpdkvhostuser

Add test flows to forward packets betwen DPDK devices and VM ports::

    # Clear current flows
    $ ovs-ofctl del-flows br0

    # Add flows
    $ ovs-ofctl add-flow br0 in_port=1,action=output:3
    $ ovs-ofctl add-flow br0 in_port=3,action=output:1
    $ ovs-ofctl add-flow br0 in_port=4,action=output:2
    $ ovs-ofctl add-flow br0 in_port=2,action=output:4

    # Dump flows
    $ ovs-ofctl dump-flows br0

Create a VM using the following configuration:

+----------------------+--------+-----------------+
| configuration        | values | comments        |
+----------------------+--------+-----------------+
| qemu version         | 2.2.0  | n/a             |
| qemu thread affinity | core 5 | taskset 0x20    |
| memory               | 4GB    | n/a             |
| cores                | 2      | n/a             |
| Qcow2 image          | CentOS7| n/a             |
| mrg_rxbuf            | off    | n/a             |
+----------------------+--------+-----------------+

You can do this directly with QEMU via the ``qemu-system-x86_64`` application::

    $ export VM_NAME=vhost-vm
    $ export GUEST_MEM=3072M
    $ export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
    $ export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch

    $ taskset 0x20 qemu-system-x86_64 -name $VM_NAME -cpu host -enable-kvm \
      -m $GUEST_MEM -drive file=$QCOW2_IMAGE --nographic -snapshot \
      -numa node,memdev=mem -mem-prealloc -smp sockets=1,cores=2 \
      -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on \
      -chardev socket,id=char0,path=$VHOST_SOCK_DIR/dpdkvhostuser0 \
      -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
      -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=off \
      -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser1 \
      -netdev type=vhost-user,id=mynet2,chardev=char1,vhostforce \
      -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mrg_rxbuf=off

For a explanation of this command, along with alternative approaches such as
booting the VM via libvirt, refer to :doc:`/topics/dpdk/vhost-user`.

Once the guest is configured and booted, configure DPDK packet forwarding
within the guest. To accomplish this, build the ``testpmd`` application as
described in :ref:`dpdk-testpmd`. Once compiled, run the application::

    $ cd $DPDK_DIR/app/test-pmd;
    $ ./testpmd -c 0x3 -n 4 --socket-mem 1024 -- \
        --burst=64 -i --txqflags=0xf00 --disable-hw-vlan
    $ set fwd mac retry
    $ start

When you finish testing, bind the vNICs back to kernel::

    $ $DPDK_DIR/tools/dpdk-devbind.py --bind=virtio-pci 0000:00:03.0
    $ $DPDK_DIR/tools/dpdk-devbind.py --bind=virtio-pci 0000:00:04.0

.. note::

  Valid PCI IDs must be passed in above example. The PCI IDs can be retrieved
  like so::

      $ $DPDK_DIR/tools/dpdk-devbind.py --status

More information on the dpdkvhostuser ports can be found in
:doc:`/topics/dpdk/vhost-user`.

PHY-VM-PHY (vHost Loopback) (Kernel Forwarding)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`dpdk-vhost-loopback` details steps for PHY-VM-PHY loopback
testcase and packet forwarding using DPDK testpmd application in the Guest VM.
For users wishing to do packet forwarding using kernel stack below, you need to
run the below commands on the guest::

    $ ifconfig eth1 1.1.1.2/24
    $ ifconfig eth2 1.1.2.2/24
    $ systemctl stop firewalld.service
    $ systemctl stop iptables.service
    $ sysctl -w net.ipv4.ip_forward=1
    $ sysctl -w net.ipv4.conf.all.rp_filter=0
    $ sysctl -w net.ipv4.conf.eth1.rp_filter=0
    $ sysctl -w net.ipv4.conf.eth2.rp_filter=0
    $ route add -net 1.1.2.0/24 eth2
    $ route add -net 1.1.1.0/24 eth1
    $ arp -s 1.1.2.99 DE:AD:BE:EF:CA:FE
    $ arp -s 1.1.1.99 DE:AD:BE:EF:CA:EE

PHY-VM-PHY (vHost Multiqueue)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

vHost Multiqueue functionality can also be validated using the PHY-VM-PHY
configuration. To begin, follow the steps described in :ref:`dpdk-phy-phy` to
create and initialize the database, start ovs-vswitchd and add ``dpdk``-type
devices to bridge ``br0``. Once complete, follow the below steps:

1. Configure PMD and RXQs.

   For example, set the number of dpdk port rx queues to at least 2  The number
   of rx queues at vhost-user interface gets automatically configured after
   virtio device connection and doesn't need manual configuration::

       $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0xc
       $ ovs-vsctl set Interface dpdk0 options:n_rxq=2
       $ ovs-vsctl set Interface dpdk1 options:n_rxq=2

2. Instantiate Guest VM using QEMU cmdline

   We must configure with appropriate software versions to ensure this feature
   is supported.

   .. list-table:: Recommended BIOS Settings
      :header-rows: 1

      * - Setting
        - Value
      * - QEMU version
        - 2.5.0
      * - QEMU thread affinity
        - 2 cores (taskset 0x30)
      * - Memory
        - 4 GB
      * - Cores
        - 2
      * - Distro
        - Fedora 22
      * - Multiqueue
        - Enabled

   To do this, instantiate the guest as follows::

       $ export VM_NAME=vhost-vm
       $ export GUEST_MEM=4096M
       $ export QCOW2_IMAGE=/root/Fedora22_x86_64.qcow2
       $ export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch
       $ taskset 0x30 qemu-system-x86_64 -cpu host -smp 2,cores=2 -m 4096M \
           -drive file=$QCOW2_IMAGE --enable-kvm -name $VM_NAME \
           -nographic -numa node,memdev=mem -mem-prealloc \
           -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on \
           -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser0 \
           -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce,queues=2 \
           -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mq=on,vectors=6 \
           -chardev socket,id=char2,path=$VHOST_SOCK_DIR/dpdkvhostuser1 \
           -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=2 \
           -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=6

   .. note::
     Queue value above should match the queues configured in OVS, The vector
     value should be set to "number of queues x 2 + 2"

3. Configure the guest interface

   Assuming there are 2 interfaces in the guest named eth0, eth1 check the
   channel configuration and set the number of combined channels to 2 for
   virtio devices::

       $ ethtool -l eth0
       $ ethtool -L eth0 combined 2
       $ ethtool -L eth1 combined 2

   More information can be found in vHost walkthrough section.

4. Configure kernel packet forwarding

   Configure IP and enable interfaces::

       $ ifconfig eth0 5.5.5.1/24 up
       $ ifconfig eth1 90.90.90.1/24 up

   Configure IP forwarding and add route entries::

       $ sysctl -w net.ipv4.ip_forward=1
       $ sysctl -w net.ipv4.conf.all.rp_filter=0
       $ sysctl -w net.ipv4.conf.eth0.rp_filter=0
       $ sysctl -w net.ipv4.conf.eth1.rp_filter=0
       $ ip route add 2.1.1.0/24 dev eth1
       $ route add default gw 2.1.1.2 eth1
       $ route add default gw 90.90.90.90 eth1
       $ arp -s 90.90.90.90 DE:AD:BE:EF:CA:FE
       $ arp -s 2.1.1.2 DE:AD:BE:EF:CA:FA

   Check traffic on multiple queues::

       $ cat /proc/interrupts | grep virtio

PHY-VM-PHY (IVSHMEM loopback)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

IVSHMEM can also be validated using the PHY-VM-PHY configuration. To begin, add
a userspace bridge, two ``dpdk`` (PHY) ports, and a single ``dpdkr`` port::

    # Add userspace bridge
    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

    # Add two dpdk ports
    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
    $ ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk

    # Add one dpdkr ports
    $ ovs-vsctl add-port br0 dpdkr0 -- set Interface dpdkr0 type=dpdkr

.. TODO(stephenfin): What flows should the user configure?

QEMU must be patched to enable IVSHMEM support::

    $ cd /usr/src/
    $ wget http://wiki.qemu.org/download/qemu-2.2.1.tar.bz2
    $ tar -jxvf qemu-2.2.1.tar.bz2
    $ cd /usr/src/qemu-2.2.1
    $ wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/patches/ivshmem-qemu-2.2.1.patch
    $ patch -p1 < ivshmem-qemu-2.2.1.patch
    $ ./configure --target-list=x86_64-softmmu --enable-debug --extra-cflags='-g'
    $ make -j 4

In addition, the ``cmdline_generator`` utility must be downloaded and built::

    $ mkdir -p /usr/src/cmdline_generator
    $ cd /usr/src/cmdline_generator
    $ wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/cmdline_generator/cmdline_generator.c
    $ wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/cmdline_generator/Makefile
    $ export RTE_SDK=/usr/src/dpdk-16.11
    $ export RTE_TARGET=x86_64-ivshmem-linuxapp-gcc
    $ make

Once both the patche QEMU and ``cmdline_generator`` utilities have been built,
run ``cmdline_generator`` to generate a suitable QEMU commandline, and use this
to instantiate a guest. For example::

    $ ./build/cmdline_generator -m -p dpdkr0 XXX
    $ cmdline=`cat OVSMEMPOOL`
    $ export VM_NAME=ivshmem-vm
    $ export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
    $ export QEMU_BIN=/usr/src/qemu-2.2.1/x86_64-softmmu/qemu-system-x86_64
    $ taskset 0x20 $QEMU_BIN -cpu host -smp 2,cores=2 -hda $QCOW2_IMAGE \
        -m 4096 --enable-kvm -name $VM_NAME -nographic -vnc :2 \
        -pidfile /tmp/vm1.pid $cmdline

When the guest has started, connect to it and build and run the sample
``dpdkr`` app. This application will simply loopback packets received over the
DPDK ring port::

    $ echo 1024 > /proc/sys/vm/nr_hugepages
    $ mount -t hugetlbfs nodev /dev/hugepages (if not already mounted)

    # Build the DPDK ring application in the VM
    $ export RTE_SDK=/root/dpdk-16.11
    $ export RTE_TARGET=x86_64-ivshmem-linuxapp-gcc
    $ make

    # Run dpdkring application
    $ ./build/dpdkr -c 1 -n 4 -- -n 0
    # where "-n 0" refers to ring '0' i.e dpdkr0