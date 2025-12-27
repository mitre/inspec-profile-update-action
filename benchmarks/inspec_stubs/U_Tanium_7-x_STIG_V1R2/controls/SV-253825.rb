control 'SV-253825' do
  title 'Tanium must notify system administrator and information system security officer (ISSO) when accounts are created.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail, which documents the creation of application user accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to offload those access control functions and focus on core application features and functionality.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Review the configured connections.

If no sources exist to send audit logs from Tanium to a security information and event management (SIEM) tool or email destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when accounts are created.

If no alert is configured, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Click "Create Connection" in the "Connections" section.

5. Configure sources to send audit logs from the Tanium SQL Server to a SIEM tool or email destination.

6. Work with the email administrator to configure an email destination.

7. Work with the SIEM administrator to configure an alert when accounts are created.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57277r842501_chk'
  tag severity: 'medium'
  tag gid: 'V-253825'
  tag rid: 'SV-253825r842503_rule'
  tag stig_id: 'TANS-CN-000019'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-57228r842502_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
