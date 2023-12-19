control 'SV-216528' do
  title 'The Cisco router must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Review the deny statements in all interface ACLs to determine if the log-input parameter has been configured as shown in the example below.
Note: log-input can only apply to interface bound ACLs.

ipv4 access-list BLOCK_INBOUND
 10 deny icmp any any log-input

If the router is not configured with the log-input parameter after any deny statements to note where packets have been dropped via an ACL, this is a finding.'
  desc 'fix', 'Configure the log-input parameter after any deny statements to provide the location as to where packets have been dropped via an ACL.

RP/0/0/CPU0:R3(config)#ipv4 access-list BLOCK_INBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#deny icmp any any  log-input'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17763r929027_chk'
  tag severity: 'medium'
  tag gid: 'V-216528'
  tag rid: 'SV-216528r929028_rule'
  tag stig_id: 'CISC-ND-000290'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-17760r288271_fix'
  tag 'documentable'
  tag legacy: ['SV-105535', 'V-96397']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
