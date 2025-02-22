control 'SV-45384' do
  title 'The IDPS must produce audit records containing information to establish where the event was detected, including, at a minimum, network segment, destination address, and IDPS component which detected the event.'
  desc 'Associating where the event was detected with the event log entries provides a means of investigating an attack or identifying an improperly configured IDPS. This information can be used to determine what systems may have been affected.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', 'Verify the IDPS produces audit records containing information to establish where the event was detected, including, at a minimum, network segment, destination address, and IDPS component which detected the event.

If the audit log events do not include information which establishes where the event was detected, including, at a minimum, network segment, destination address, and IDPS component which detected the event, this is a finding.'
  desc 'fix', 'Configure the IDPS to produce audit records containing information to establish where the event was detected, including, at a minimum, network segment, destination address, and IDPS component which detected the event.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42733r3_chk'
  tag severity: 'medium'
  tag gid: 'V-34542'
  tag rid: 'SV-45384r2_rule'
  tag stig_id: 'SRG-NET-000076-IDPS-00061'
  tag gtitle: 'SRG-NET-000076-IDPS-00061'
  tag fix_id: 'F-38781r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
