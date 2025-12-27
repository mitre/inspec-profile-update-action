control 'SV-108141' do
  title 'All BlackBerry server local accounts created during application installation and configuration must be disabled or removed.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FMT_SMF.1.1(2) b / IA-5(1)(a)

'
  desc 'check', 'Review the creation and deletion of the local administrator or other local accounts to determine whether all local accounts are removed from UEM and cannot be used to access UEM. For UEM, the "default user" is the local account.

On the BlackBerry UEM UI, verify the following: 
1. Log in to the UEM console.
2. From the menu bar on the left, go to Settings >> Administrators >> Users. A list of authorized users will be shown. 

All users must be assigned to a user and a role. Although roles can be defined in UEM, the default list of users is: Enterprise Administrator, security administrator, senior help desk, and junior helpdesk. 

If a default user is listed that is not assigned to a specific user, the control is out of compliance. Advise the administrator to log out and log in as the security administrator and follow the steps to delete the default user. Log back in as a defined administrator to confirm the default user is not listed in the list of users. Log out and then log in to the UEM UI credentials login screen using the default user name and password, which will return a "bad username or password response". 

If the local account (default user) is not removed from the UEM server, this is a finding.'
  desc 'fix', 'Log in to UEM 12.11 and create a local or directory user that has an email address associated with it.
1. On the menu bar, click "Settings".
2. In the left pane, click "Administrators".
3. Click "Users" and click on the "Add an administrator" icon.
4. Search for/select a user.
5. In the "Role" drop-down list, click the Security Administrator role and save. 
6. Log out and log in as the new security admin user. A prompt may appear to update the password.
7. The new security admin user can then delete the default user. The default user is the local admin account. 

See full details at https://docs.blackberry.com/en/endpoint-management/blackberry-uem/12_11/administration/management-console/adr1370874367290.'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.11'
  tag check_id: 'C-97877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99037'
  tag rid: 'SV-108141r1_rule'
  tag stig_id: 'BUEM-12-112040'
  tag gtitle: 'PP-MDM-331007'
  tag fix_id: 'F-104713r1_fix'
  tag satisfies: ['SRG-APP-000148']
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
