control 'SV-45385' do
  title 'The IDPS must produce audit records containing information to establish the source of the event, including, at a minimum, originating source address.'
  desc 'Associating the source of the event with detected events in the logs provides a means of investigating an attack or suspected attack.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', 'Verify configuration produces audit records containing information to establish the source of the event, including, at a minimum, originating source address.

If the IDPS does not produce audit records containing information to establish the source of the event, including, at a minimum, originating source address, this is a finding.'
  desc 'fix', 'Configure the IDPS to produce audit records containing information to establish the source of the event, including, at a minimum, originating source address.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42734r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34543'
  tag rid: 'SV-45385r2_rule'
  tag stig_id: 'SRG-NET-000077-IDPS-00062'
  tag gtitle: 'SRG-NET-000077-IDPS-00062'
  tag fix_id: 'F-38782r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
