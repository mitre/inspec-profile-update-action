control 'SV-80887' do
  title 'First-hop redundancy services must be configured to delay any preempt to provide enough time for the Internet Gateway Protocol (IGP) to stabilize.'
  desc 'The Layer 2 connection between the nodes providing first-hop redundancy comes up quickly. If the preemption takes effect prior to the routing protocol converging, traffic is black holed. Traffic will go to the active router that does not have full routing information. It may take several seconds for the IGP to exchange all the routes, longer than the Hot Standby Router Protocol (HSRP), Virtual Router Redundancy Protocol (VRRP), or Gateway Load Balancing Protocol (GLPB) transition. The recommended practice is to delay the preemption action until after the IGP has a chance to stabilize.'
  desc 'check', 'All routers or multilayer switches providing first-hop redundancy services must be configured to delay preemption to provide enough time for the IGP to stabilize. Review the router or multilayer switch providing first-hop redundancy services and verify that the preemption delay is configured.

If preemption delay is not configured, this is a finding.

Following is an HSRP configuration example that delays the preemption by 30 seconds.

interface GigabitEthernet 0/0/0
ip address 10.11.0.2 255.255.255.0
standby 1 priority 110
standby 1 ip 10.21.0.1
standby 1 preempt
standby 1 preempt delay minimum 30

Following is a VRRP configuration example that delays the preemption by 30 seconds.

interface GigabitEthernet 0/0/0
ip address 10.11.0.2 255.255.255.0
vrrp 1 priority 110
vrrp 1 ip 10.21.0.1
vrrp 1 preempt delay minimum 30

For VRRP implementations, a preemptive scheme is enabled by default. If preemption is disabled using the no vrrp preempt command, the virtual router backup that is elected to become virtual router master remains the master until the original virtual router master recovers and becomes master again.'
  desc 'fix', 'Configure each router and multilayer switch providing first-hop redundancy services to be configured to delay the preempt to provide enough time for the IGP to stabilize.

Note: The amount of delay will be based on the number of IGP routes.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67043r2_chk'
  tag severity: 'low'
  tag gid: 'V-66397'
  tag rid: 'SV-80887r2_rule'
  tag stig_id: 'NET2017'
  tag gtitle: 'NET2017'
  tag fix_id: 'F-72473r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
