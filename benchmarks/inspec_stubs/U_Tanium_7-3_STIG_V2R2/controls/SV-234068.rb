control 'SV-234068' do
  title 'Tanium must notify SA and ISSO for account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual application users or for identifying the application processes themselves.

In order to detect and respond to events that affect user accessibility and application processing, applications must audit account removal actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured sources.

If no sources exists to send audit logs from the Tanium SQL Server to a SIEM tool or Email Destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when accounts are deleted.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Configure sources to send audit logs from the Tanium SQL Server to a SIEM tool or Email Destination.

Work with Email administrator to configure Email destination.

Work with the SIEM administrator to configure an alert when accounts are deleted.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37253r610704_chk'
  tag severity: 'medium'
  tag gid: 'V-234068'
  tag rid: 'SV-234068r612749_rule'
  tag stig_id: 'TANS-CN-000033'
  tag gtitle: 'SRG-APP-000294'
  tag fix_id: 'F-37218r610705_fix'
  tag 'documentable'
  tag legacy: ['SV-102209', 'V-92107']
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
