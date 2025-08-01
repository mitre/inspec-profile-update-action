control 'SV-207120' do
  title 'The router must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as router components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured router.'
  desc 'check', 'The router must log all packets that have been dropped via the access control list (ACL). 

If the router fails to log all packets that have been dropped via the ACL, this is a finding.

Log output must contain an interface name as to where the packet was filtered.

If the logged output does not contain an interface name as to where the packet was filtered, this is a finding.'
  desc 'fix', 'Configure the router to record the interface in the log record for packets being dropped.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7381r382253_chk'
  tag severity: 'medium'
  tag gid: 'V-207120'
  tag rid: 'SV-207120r604135_rule'
  tag stig_id: 'SRG-NET-000076-RTR-000001'
  tag gtitle: 'SRG-NET-000076'
  tag fix_id: 'F-7381r382254_fix'
  tag 'documentable'
  tag legacy: ['V-78231', 'SV-92937']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
