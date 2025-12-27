control 'SV-254925' do
  title 'Tanium must notify system administrators and ISSO for account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Review the configured connections.

If no sources exist to send audit logs from the Tanium SQL Server to a SIEM tool or email destination, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when accounts are disabled.

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
  tag check_id: 'C-58538r867673_chk'
  tag severity: 'medium'
  tag gid: 'V-254925'
  tag rid: 'SV-254925r867675_rule'
  tag stig_id: 'TANS-AP-000710'
  tag gtitle: 'SRG-APP-000293'
  tag fix_id: 'F-58482r867674_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
