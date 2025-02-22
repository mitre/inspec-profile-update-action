control 'SV-101923' do
  title 'Authentication of MDM platform accounts must be configured so they are implemented via an enterprise directory service.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MobileIron Core v10 server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MobileIron Core v10 server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'On the MDM console, do the following:
1. Logon to the MobileIron Core Server administrator portal as a user with the "security configuration administrator" role using a web browser.
2. Select "Services" on the web page.
3. Select "LDAP" on the web page.
4. Click the "edit" icon on an existing LDAP configuration to be tested.
5. Select "Test" on the LDAP server configuration dialog.
6. Enter a valid LDAP user ID.
7. Select "Submit".
8. Verify the LDAP query is successful and shows user attributes in a dialog box.

If the MDM server does not leverage the MDM platform user accounts and groups for the MDM server user identification and authentication, this is a finding.'
  desc 'fix', 'Configure the MDM server to leverage the MDM platform user accounts and groups for MDM server user identification and authentication.

On the MDM console, do the following:
1. Logon to the MobileIron Core Server administrator portal as a user with the "security configuration administrator" role using a web browser.
2. Select "Services" on the web page.
3. Select "LDAP" on the web page.
4. Select "Add New" (or click the "edit" icon on an existing LDAP configuration).
5. Complete the LDAP configuration dialog providing the URL for the LDAP server, alternate URL if there is a backup LDAP server, user ID and password for the LDAP server, and for additional settings see "Configuring LDAP Servers" section in the On-Premise Installation Guide.
6. Select "Save" to save the LDAP configuration.'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91821'
  tag rid: 'SV-101923r1_rule'
  tag stig_id: 'MICR-10-000660'
  tag gtitle: 'PP-MDM-314003'
  tag fix_id: 'F-98023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
