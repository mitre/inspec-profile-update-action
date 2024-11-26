control 'SV-88791' do
  title 'The Cisco IOS XE router must enforce that any interface used for out-of-band management traffic is configured to be passive for the Interior Gateway Protocol that is utilized on that management interface.'
  desc 'The out-of-band management access switch will connect to the management interface of the managed network elements. The management interface can be a true out-of-band management interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will directly connect to the out-of-band management network.

An out-of-band management interface does not forward transit traffic, thereby, providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an out-of-band management port, the interface functioning as the management interface must be configured so that management traffic, both data plane and control plane, does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Review the configuration of the Cisco IOS XE router to verify the management interface is configured as passive for the Interior Gateway Protocol instance for the managed network.

The configuration would look similar to the following example:

router ospf 1
 
 area 1 authentication message-digest
 passive-interface GigabitEthernet0/0
 network 200.30.3.0 0.0.0.255 area 1

If the management interface is not configured as passive for the Interior Gateway Protocol instance for the managed network, this is a finding.'
  desc 'fix', 'Configure the management interface of the Cisco IOS XE router as passive for the Interior Gateway Protocol instance configured for the managed network.

The configuration will look similar to the example below:

outer ospf 1
 
 area 1 authentication message-digest
 passive-interface GigabitEthernet0/0
 network 200.30.3.0 0.0.0.255 area 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74203r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74117'
  tag rid: 'SV-88791r2_rule'
  tag stig_id: 'CISR-RT-000011'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-80659r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
