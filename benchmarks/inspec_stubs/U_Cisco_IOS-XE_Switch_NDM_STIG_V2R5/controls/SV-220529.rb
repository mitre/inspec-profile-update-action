control 'SV-220529' do
  title 'The Cisco switch must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Review the deny statements in all ACLs to determine if the log-input parameter has been configured as shown in the example below:

ip access-list extended BLOCK_INBOUND
 deny icmp any any log-input

If the switch is not configured with the log-input parameter after any deny statements to note where packets have been dropped via an ACL, this is a finding.'
  desc 'fix', 'Configure the log-input parameter after any deny statements to provide the location as to where packets have been dropped via an ACL.

SW1(config)#ip access-list extended BLOCK_INBOUND
SW1(config-ext-nacl)#deny icmp any any log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22244r508531_chk'
  tag severity: 'medium'
  tag gid: 'V-220529'
  tag rid: 'SV-220529r879565_rule'
  tag stig_id: 'CISC-ND-000290'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-22233r508532_fix'
  tag 'documentable'
  tag legacy: ['SV-110513', 'V-101409']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
