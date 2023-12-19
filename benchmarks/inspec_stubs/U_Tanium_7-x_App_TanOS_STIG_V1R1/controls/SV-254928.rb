control 'SV-254928' do
  title 'The Tanium Application Server must be configured with a connector to sync to Microsoft Active Directory for account management functions.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the operational responsibility of the System Administrator for the Windows Operation System Active Directory.

'
  desc 'check', 'Console Users:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "LDAP/AD Sync Configurations".

4. Verify a sync exists under "Enabled Servers".

If no sync exists, this is a finding.

If sync exists under "Disabled Servers" and there are no Enabled Servers, this is a finding.

Local TanOS Accounts:

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role, or any additional user with administrative privileges.

3. Enter "C" for "User Administration Menu," and then press "Enter".

4. Enter "L" for "Local Tanium User Management," and then press "Enter".

5. Press "2" for "Manage Local User(s)," and then press "Enter".

If there are any users other than the Documented approved local users this is a finding.'
  desc 'fix', 'Console Users:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "LDAP/AD Sync Configurations".

4. Click "Add Server"

5. Complete the settings using guidance from https://docs.tanium.com/platform_user/platform_user/console_using_ldap.html.

6. Click "Show Preview to Continue".

7. Review the users and groups to be imported.

8. Click "Save".

Local TanOS Accounts:

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role, or any additional user with administrative privileges.

3. Enter "C" for "User Administration Menu," and then press "Enter".

4. Enter "L" for "Local Tanium User Management," and then press "Enter".

5. Press "2" for "Manage Local User(s)," and then press "Enter".

6. Work with Tanium System Administrator to either document approved accounts or remove nonapproved accounts.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58541r867682_chk'
  tag severity: 'medium'
  tag gid: 'V-254928'
  tag rid: 'SV-254928r867684_rule'
  tag stig_id: 'TANS-AP-000765'
  tag gtitle: 'SRG-APP-000317'
  tag fix_id: 'F-58485r867683_fix'
  tag satisfies: ['SRG-APP-000233']
  tag 'documentable'
  tag cci: ['CCI-001084', 'CCI-002142']
  tag nist: ['SC-3', 'AC-2 (10)']
end
