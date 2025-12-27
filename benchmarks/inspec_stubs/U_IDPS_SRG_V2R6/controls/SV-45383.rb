control 'SV-45383' do
  title 'The IDPS must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing the time (date/time) an event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. Associating the date and time the event occurred with each event log entry provides a means of investigating an attack or identifying an improperly configured IDPS. 

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', 'Verify the entries sent to the audit log include the date and time of each event.

If the audit log event records do not include the date and time the events occurred, this is a finding.'
  desc 'fix', 'Configure the IDPS components to include the date time stamp of events in log messages.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42732r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34541'
  tag rid: 'SV-45383r2_rule'
  tag stig_id: 'SRG-NET-000075-IDPS-00060'
  tag gtitle: 'SRG-NET-000075-IDPS-00060'
  tag fix_id: 'F-38780r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
