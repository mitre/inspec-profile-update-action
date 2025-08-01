control 'SV-93337' do
  title 'Tanium must notify the SA and ISSO of account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of application user accounts and notifies administrators and ISSOs exists. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, applications must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Sources.

If no "Sources" exists to send audit logs from the Tanium SQL Server to a SIEM tool, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when account enabling actions are performed.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Configure "Sources" to send audit logs from the Tanium SQL Server to a SIEM tool.

Work with the SIEM administrator to configure an alert when account enabling actions are performed.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78201r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78631'
  tag rid: 'SV-93337r1_rule'
  tag stig_id: 'TANS-CN-000021'
  tag gtitle: 'SRG-APP-000320'
  tag fix_id: 'F-85367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
