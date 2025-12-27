control 'SV-221939' do
  title 'Splunk Enterprise must notify the System Administrator (SA) and Information System Security Officer (ISSO) when account events are received (creation, deletion, modification, disabling).'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. Sending notification of account creation events to the SA and ISSO is one method for mitigating this risk.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to offload those access control functions and focus on core application features and functionality.

'
  desc 'check', 'If the Splunk instance is used for Tier 2 CSSP (formerly CND-SP) or JRSS analysis, this check is N/A.

Interview the SA to verify that a process exists to notify the SA and ISSO when account events are received for all devices and hosts within its scope of coverage.

Interview the ISSO to confirm receipt of this notification.

If Splunk Enterprise is not configured to notify the SA and ISSO when account events are received for all devices and hosts within its scope of coverage, this is a finding.'
  desc 'fix', 'If the Splunk instance is used for Tier 2 CSSP (formerly CND-SP) or JRSS analysis, this fix is N/A.

Configure Splunk Enterprise, using the reporting and notification tools, to notify the SA and ISSO when account events are received for all devices and hosts within its scope of coverage.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23653r420285_chk'
  tag severity: 'low'
  tag gid: 'V-221939'
  tag rid: 'SV-221939r879669_rule'
  tag stig_id: 'SPLK-CL-000200'
  tag gtitle: 'SRG-APP-000291-AU-000200'
  tag fix_id: 'F-23642r420286_fix'
  tag satisfies: ['SRG-APP-000291-AU-000200', 'SRG-APP-000292-AU-000420', 'SRG-APP-000293-AU-000430', 'SRG-APP-000294-AU-000440']
  tag 'documentable'
  tag legacy: ['SV-111369', 'V-102425']
  tag cci: ['CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
