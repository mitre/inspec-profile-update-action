control 'SV-93333' do
  title 'Tanium must notify system administrators and ISSO when accounts are created.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO) exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Sources.

If no "Sources" exists to send audit logs from the Tanium SQL Server to a SIEM tool, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when accounts are created.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Configure a "Sources" to send audit logs from the Tanium SQL Server to a SIEM tool.

Work with the SIEM administrator to configure an alert when accounts are created.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78197r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78627'
  tag rid: 'SV-93333r1_rule'
  tag stig_id: 'TANS-CN-000019'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-85363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
