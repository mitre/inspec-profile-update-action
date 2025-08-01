control 'SV-251670' do
  title 'Splunk Enterprise must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) of all audit failure events, such as loss of communications with hosts and devices, or if log records are no longer being received.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit function and application operation may be adversely affected.'
  desc 'check', 'Interview the SA to verify that a report exists to notify the SA and ISSO of any audit failure, such as loss of communication or logs no longer being collected.

Interview the ISSO to confirm receipt of this report.

If a report does not exist to notify the SA and ISSO of audit failure events, or the ISSO does not confirm receipt of the report, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise, using the reporting and notification tools, to create a report with notification to the SA and ISSO of any audit failure events, such as loss of communication or logs no longer being collected.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55108r808244_chk'
  tag severity: 'low'
  tag gid: 'V-251670'
  tag rid: 'SV-251670r808246_rule'
  tag stig_id: 'SPLK-CL-000170'
  tag gtitle: 'SRG-APP-000360-AU-000130'
  tag fix_id: 'F-55062r808245_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
