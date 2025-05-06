control 'SV-254924' do
  title 'Tanium must notify system administrators and ISSO when accounts are modified.'
  desc 'When application accounts are modified, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account modification events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Review the configured connections.

If no sources exist to send audit logs from the Tanium Database to a SIEM tool or email destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when accounts are modified.

If there is no alert configured, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Click "Create Connection" in the "Connections" section.

5. Configure sources to send audit logs from the Tanium SQL Server to a SIEM tool or email destination.

6. Work with email administrator to configure email destination.

7. Work with the SIEM administrator to configure an alert when accounts are modified.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58537r867670_chk'
  tag severity: 'medium'
  tag gid: 'V-254924'
  tag rid: 'SV-254924r867672_rule'
  tag stig_id: 'TANS-AP-000705'
  tag gtitle: 'SRG-APP-000292'
  tag fix_id: 'F-58481r867671_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
