control 'SV-215673' do
  title 'The Cisco router must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Review the deny statements in all ACLs to determine if the log-input parameter has been configured as shown in the example below.

ip access-list extended BLOCK_INBOUND
 deny  icmp any any log-input

If the router is not configured with the log-input parameter after any deny statements to note where packets have been dropped via an ACL, this is a finding.'
  desc 'fix', 'Configure the log-input parameter after any deny statements to provide the location as to where packets have been dropped via an ACL.

R1(config)#ip access-list extended BLOCK_INBOUND
R1(config-ext-nacl)#deny icmp any any log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16867r285981_chk'
  tag severity: 'medium'
  tag gid: 'V-215673'
  tag rid: 'SV-215673r521266_rule'
  tag stig_id: 'CISC-ND-000290'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-16865r285982_fix'
  tag 'documentable'
  tag legacy: ['SV-105181', 'V-96043']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
