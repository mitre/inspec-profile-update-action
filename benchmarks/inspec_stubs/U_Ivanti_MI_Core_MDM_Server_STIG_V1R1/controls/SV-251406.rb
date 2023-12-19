control 'SV-251406' do
  title 'The Ivanti MobileIron Core server must be configured to use a DoD Central Directory Service to provide multifactor authentication for network access to privileged and non-privileged accounts.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos). 

'
  desc 'check', 'On the MDM console, do the following:
1. Log in to the MobileIron Core Server administrator portal as a user with the security configuration administrator role using a web browser.
2. Select "Services" on the web page.
3. Select "LDAP" on the web page.
4. Click the edit icon on an existing LDAP configuration to be tested.
5. Select "Test" on the LDAP server configuration dialog.
6. Enter a valid LDAP user ID and select "Submit".
7. Verify the LDAP query is successful and shows user attributes in a dialog box.

Note: All administrator accounts must be configured for LDAP authentication unless a select number of local accounts have been approved by the AO. Verify AO approval if local accounts (not using LDAP authentication) are configured on the Core server.

If the MDM server does not leverage the MDM platform user accounts and groups for MDM server user identification and authentication, this is a finding.'
  desc 'fix', 'Configure the MDM server to leverage the MDM platform user accounts and groups for MDM server user identification and authentication.

On the MDM console, do the following:
1. Log in to the MobileIron Core Server administrator portal as a user with the security configuration administrator role using a web browser.
2. Select "Services" on the web page.
3. Select "LDAP" on the web page.
4. Select "Add New" (or click the edit icon on an existing LDAP configuration).
5. Complete the LDAP configuration dialog providing the URL for the LDAP server, alternate URL if there is a backup LDAP server, user ID and password for the LDAP server, and for additional settings see "Configuring LDAP Servers" section in the On-Premise Installation Guide.
6. Select "Save" to save the LDAP configuration.

Note: All administrator accounts will be configured to use LDAP-based authentication, unless there is an operational need for a select number of local accounts, with the approval of the AO.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54841r806348_chk'
  tag severity: 'medium'
  tag gid: 'V-251406'
  tag rid: 'SV-251406r806350_rule'
  tag stig_id: 'IMIC-11-004200'
  tag gtitle: 'SRG-APP-000149-UEM-000083'
  tag fix_id: 'F-54794r806349_fix'
  tag satisfies: ['FIA \nReference: PP-MDM-414003']
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
