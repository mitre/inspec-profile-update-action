control 'SV-251658' do
  title 'Splunk Enterprise must notify the System Administrator (SA) and Information System Security Officer (ISSO) when account events are received (creation, deletion, modification, or disabling).'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator and ISSO is one method for mitigating this risk.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.

'
  desc 'check', 'Interview the SA to verify that a report exists to notify the SA and ISSO when account events are received for all devices and hosts within its scope of coverage.

Interview the ISSO to confirm receipt of this report.

If Splunk Enterprise is not configured to notify the SA and ISSO when account events are received for all devices and hosts within its scope of coverage, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise, using the reporting and notification tools, to notify the SA and ISSO when account events are received for all devices and hosts within its scope of coverage.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55096r808208_chk'
  tag severity: 'low'
  tag gid: 'V-251658'
  tag rid: 'SV-251658r808210_rule'
  tag stig_id: 'SPLK-CL-000020'
  tag gtitle: 'SRG-APP-000291-AU-000200'
  tag fix_id: 'F-55050r808209_fix'
  tag satisfies: ['SRG-APP-000291-AU-000200', 'SRG-APP-000292-AU-000420', 'SRG-APP-000294-AU-000430', 'SRG-APP-000294-AU-000440']
  tag 'documentable'
  tag cci: ['CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
