control 'SV-253827' do
  title 'Tanium must notify the system administrator and information system security officer (ISSO) of account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to offload those access control functions and focus on core application features and functionality.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Review the configured sources.

If no sources exists to send audit logs from the Tanium SQL Server to a security information and event management (SIEM) tool or email destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when account-enabling actions are performed.

If no alert is configured, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Configure sources to send audit logs from the Tanium SQL Server to a SIEM tool or email destination.

5. Work with the email administrator to configure an email destination.

6. Work with the SIEM administrator to configure an alert when account-enabling actions are performed.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57279r842507_chk'
  tag severity: 'medium'
  tag gid: 'V-253827'
  tag rid: 'SV-253827r850159_rule'
  tag stig_id: 'TANS-CN-000021'
  tag gtitle: 'SRG-APP-000320'
  tag fix_id: 'F-57230r842508_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
