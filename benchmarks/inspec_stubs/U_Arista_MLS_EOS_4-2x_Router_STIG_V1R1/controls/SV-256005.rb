control 'SV-256005' do
  title 'The out-of-band management (OOBM) Arista gateway router must be configured to have separate IGP instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Verify the OOBM interface is an adjacency in the Interior Gateway Protocol routing domain for the management network.

Verify interface configuration that the OOBM management network subnet is configured.

Step 1: To verify ospf process 100 interface is configured, execute the command "show run int YY". To verify vrf instance, execute "show vrf". Verify the OOBM vrf instance is configured.

vrf instance OOBM
ip routing vrf OOBM 
interface Vlan 2
   description Connection to OOBM-LAN-Ethernet4
   vrf OOBM
   mtu 9214
   no routerport
   ip address 10.1.12.7/31

Step 2: To verify OSPF process is configured as OOBM management network, execute the command "show run section router ospf 100".

router ospf 100 vrf OOBM
 network 10.1.12.0/24 area 0.0.0.0

Step 3: To verify OSPF process 200 is enabled on a private network without any connectivity with the OSPF process in management network, execute the command "show run int YY". Verify the LAN vrf instance is configured.

vrf instance LAN
ip routing vrf LAN

interface Ethernet8
   vrf LAN
   description Connection to Private-LAN-Ethernet4
   mtu 9214
   no routerport
   ip address 172.16.35.135/31

Step 4: To verify OSPF process 200 is configured as Private-LAN network, execute the command "show run section router ospf 200".

router ospf 200 vrf LAN
 network 172.16.35.0/24 area 0.0.0.0

If the router does not enforce that Interior Gateway Protocol instances configured on the OOBM gateway router peer only with their own routing domain, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista router to enforce that Interior Gateway Protocol instances configured on the OOBM gateway router peer only with their own routing domain.

Configuring OSPF:

Step 1: Configure the interface and OOBM vrf instance.

vrf instance OOBM
ip routing vrf OOBM 

LEAF-1A(config)#interface Vlan 2
LEAF-1A(config-if-Vl2)#description Connection to OOBM-LAN-Ethernet4
LEAF-1A(config-if-Vl2)#vrf OOBM
LEAF-1A(config-if-Vl2)#mtu 9214
LEAF-1A(config-if-Vl2)#no routerport
LEAF-1A(config-if-Vl2)#ip address 10.1.12.7/31

Step 2: Advertise the subnet in OSPF process 100.

LEAF-1A(config-router-rip)#router ospf 100 vrf OOBM
LEAF-1A(config-router-ospf)#network 10.1.12.0/24 area 0.0.0.0

Step 3: Configure the interface and LAN vrf instance.

vrf instance LAN
ip routing vrf LAN 

LEAF-1A(config)#interface Ethernet8
LEAF-1A(config-if-Et8)#description Connection to Private-LAN-Ethernet4
LEAF-1A(config-if-Et8)#vrf LAN
LEAF-1A(config-if-Et8)#mtu 9214
LEAF-1A(config-if-Et8)#no routerport
LEAF-1A(config-if-Et8)#ip address 172.16.35.135/31

Step 4: Advertise the subnet in OSPF process 200.

LEAF-1A(config-router-ospf)#router ospf 200 vrf LAN
LEAF-1A(config-router-rip)#network 172.16.35.0/24 area 0.0.0.0'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59681r882355_chk'
  tag severity: 'medium'
  tag gid: 'V-256005'
  tag rid: 'SV-256005r882357_rule'
  tag stig_id: 'ARST-RT-000190'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-59624r882356_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
