control 'SV-251671' do
  title 'Splunk Enterprise must notify the System Administrator (SA) or Information System Security Officer (ISSO) if communication with the host and devices within its scope of coverage is lost.'
  desc 'If the system were to continue processing after audit failure, actions could be taken on the system that could not be tracked and recorded for later forensic analysis. To perform this function, some type of heartbeat configuration with all of the devices and hosts must be configured.'
  desc 'check', 'If the Splunk instance is used for Tier 2 CSSP (formerly CND-SP) or JRSS analysis, this check is N/A.

Interview the SA to verify that a report exists to notify the SA and ISSO of any audit failure, such as loss of communication or logs no longer being collected.

Interview the ISSO to confirm receipt of this report.

If a report does not exist to notify the SA and ISSO of audit failure events, or the ISSO does not confirm receipt of this report, this is a finding.'
  desc 'fix', 'If the Splunk instance is used for Tier 2 CSSP (formerly CND-SP) or JRSS analysis, this check is N/A.

Configure Splunk Enterprise, using the reporting and notification tools, to create a report with notification to the SA and ISSO of any audit failure events, such as loss of communication or logs no longer being collected.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55109r808247_chk'
  tag severity: 'low'
  tag gid: 'V-251671'
  tag rid: 'SV-251671r808249_rule'
  tag stig_id: 'SPLK-CL-000180'
  tag gtitle: 'SRG-APP-000361-AU-000140'
  tag fix_id: 'F-55063r808248_fix'
  tag 'documentable'
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
