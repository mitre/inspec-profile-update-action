control 'SV-253815' do
  title 'The Tanium Application Server must be configured with a connector to sync to Microsoft Active Directory for account management functions.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the operational responsibility of the system administrator for the Windows Operating System Active Directory.

'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "LDAP/AD Sync Configurations". 

4. Verify a sync exists under "Enabled Servers".

If no sync exists, this is a finding.

If sync exists under "Disabled Servers" and there are no Enabled Servers, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "LDAP/AD Sync Configurations".

4. Click "Add Server".

5. Complete the settings using guidance from https://docs.tanium.com/platform_user/platform_user/console_using_ldap.html.

6. Click "Show Preview to Continue".

7. Review the users and groups to be imported.

8. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57267r842471_chk'
  tag severity: 'medium'
  tag gid: 'V-253815'
  tag rid: 'SV-253815r858409_rule'
  tag stig_id: 'TANS-CN-000002'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-57218r842472_fix'
  tag satisfies: ['SRG-APP-000317']
  tag 'documentable'
  tag cci: ['CCI-001084', 'CCI-002142']
  tag nist: ['SC-3', 'AC-2 (10)']
end
