control 'SV-45382' do
  title 'The IDPS must produce audit records containing sufficient information to establish what type of event occurred, including, at a minimum, event descriptions, policy filter, rule or signature invoked, port, protocol, and criticality level/alert code or description.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. Associating an event type with each event log entry provides a means of investigating an attack or identifying an improperly configured IDPS.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', 'Verify the entries sent to the audit log include, at a minimum, event descriptions, policy filter, rule or signature invoked, port, protocol, criticality level/alert code or description.

If the audit log event records does not include, at a minimum, event descriptions, policy filter, rule signature invoked, port, protocol, and criticality level/alert code or description, this is a finding.'
  desc 'fix', 'Configure the IDPS components to ensure entries sent to the audit log include sufficient information to determine the type or category for each audit event recorded in the audit log, including, at a minimum, event descriptions, policy filter, rule or signature invoked, port, protocol, and criticality level/alert code or description.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42731r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34540'
  tag rid: 'SV-45382r2_rule'
  tag stig_id: 'SRG-NET-000074-IDPS-00059'
  tag gtitle: 'SRG-NET-000074-IDPS-00059'
  tag fix_id: 'F-38779r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
