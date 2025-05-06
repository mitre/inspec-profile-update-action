control 'SV-88787' do
  title 'The Cisco IOS XE router must enforce that Interior Gateway Protocol instances configured on the out-of-band management gateway router only peer with their own routing domain.'
  desc 'If the gateway router is not a dedicated device for the out-of-band management network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'Verify that the OOBM interface is an adjacency only in the IGP routing domain for the management network.

The following would be an example where EIGRP is run on the management network 10.0.0.0 and OSPF in the managed network 172.20.0.0.

The network 10.1.20.0/24 is the OOBM backbone and 10.1.1.0 is the local management LAN connecting to the OOBM interfaces of the managed network (i.e., the private and service network) elements. 

interface Serial0/0 
description to_OOBM_Backbone 
ip address 10.1.20.3 255.255.255.0 
!
interface FastEthernet 0/0 
description Enclave_Management_LAN 
ip address 10.1.1.1 255.255.255.0  
!
interface FastEthernet 0/1 
description to_our_PrivateNet 
ip address 172.20.4.2 255.255.255.0  
!
interface FastEthernet 0/2 
description to_our_ServiceNet 
ip address 172.20.5.2 255.255.255.0  
! 
router ospf 1 
network 172.20.0.0 
! 
router eigrp 12 
network 10.0.0.0 

If the OOBM interface is not an adjacency only in the IGP routing domain for the management network, this is a finding.'
  desc 'fix', 'Ensure that multiple IGP instances configured on the OOBM gateway router peer only with their appropriate routing domain.

Verify that the all interfaces are configured for the appropriate IGP instance.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74199r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74113'
  tag rid: 'SV-88787r2_rule'
  tag stig_id: 'CISR-RT-000009'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-80655r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
