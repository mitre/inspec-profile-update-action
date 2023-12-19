control 'SV-234062' do
  title 'Tanium must notify SA and ISSO when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail, which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO) exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured sources.

If no sources exists to send audit logs from the Tanium SQL Server to a SIEM tool or Email Destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when accounts are modified.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Configure a source to send audit logs from the Tanium SQL Server to a SIEM tool or Email Destination.

Work with Email administrator to configure Email destination.

Work with the SIEM administrator to configure an alert when accounts are modified.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37247r610686_chk'
  tag severity: 'medium'
  tag gid: 'V-234062'
  tag rid: 'SV-234062r612749_rule'
  tag stig_id: 'TANS-CN-000020'
  tag gtitle: 'SRG-APP-000292'
  tag fix_id: 'F-37212r610687_fix'
  tag 'documentable'
  tag legacy: ['SV-102197', 'V-92095']
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
