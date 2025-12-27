control 'SV-88799' do
  title 'The Cisco IOS XE router must be configured to disable non-essential capabilities.'
  desc 'A compromised router introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Verify that the Cisco IOS XE router does not have any unnecessary or non-secure ports, protocols and services enabled. For example, the following commands should not be in the configuration:

ip bootp server
ip identd
ip finger
ip http-server
ip rcmd rcp-enable
ip rcmd rsh-enable
service config
service finger
service tcp-small-servers
service udp-small-servers
service pad

If any unnecessary or non-secure ports, protocols or services are enabled, this is a finding.'
  desc 'fix', 'Disable all unnecessary or non-secure ports, protocols and services.

If any of the following commands are in the configuration, remove them.

service udp-small-servers
service tcp-small-servers
service finger
service pad
ip dns server
ip identd
ip finger
ip http-server
ip rcmd rcp-enable
ip rcmd rsh-enable
ip bootp server
service config'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74211r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74125'
  tag rid: 'SV-88799r2_rule'
  tag stig_id: 'CISR-RT-000015'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-80667r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
