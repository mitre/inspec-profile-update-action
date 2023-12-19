control 'SV-234063' do
  title 'The Tanium application must notify SA and ISSO of account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure the existence of an audit trail, which documents the creation of application user accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, applications must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured sources.

If no sources exists to send audit logs from the Tanium SQL Server to a SIEM tool or Email Destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when account-enabling actions are performed.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Configure sources to send audit logs from the Tanium SQL Server to a SIEM tool or Email Destination.

Work with Email administrator to configure Email destination.

Work with the SIEM administrator to configure an alert when account-enabling actions are performed.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37248r610689_chk'
  tag severity: 'medium'
  tag gid: 'V-234063'
  tag rid: 'SV-234063r612749_rule'
  tag stig_id: 'TANS-CN-000021'
  tag gtitle: 'SRG-APP-000320'
  tag fix_id: 'F-37213r610690_fix'
  tag 'documentable'
  tag legacy: ['SV-102199', 'V-92097']
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
