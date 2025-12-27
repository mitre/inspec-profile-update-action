control 'SV-108697' do
  title 'All Jamf Pro EMM server local accounts created during application installation and configuration must be disabled.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire Jamf Pro EMM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the Jamf Pro EMM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FMT_SMF.1.1(2) b / IA-5(1)(a)

'
  desc 'check', 'Verify all local accounts on the Jamf Pro EMM server have been disabled. Note: the server service account is not disabled.

1. Log in to the Jamf pro EMM console.
2. Open "Settings".
3. Verify all Jamf Pro User Accounts & Groups have been disabled.

If all local accounts on the Jamf Pro EMM server have not been disabled, this is a finding.'
  desc 'fix', 'Disable all local accounts on the Jamf Pro EMM server with the following procedure. Note: The server service account should not be disabled.

1. Open "Settings".
2. Select "Jamf Pro User Accounts & Groups".
3. Select the user/accounts that need to be disabled.
4. Upon selection, click on the "Edit" button.
5. Change the "Access Status" to "Disabled".
6. Click "Save".
7. Repeat steps 3-6 for all local accounts.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98443r2_chk'
  tag severity: 'medium'
  tag gid: 'V-99593'
  tag rid: 'SV-108697r1_rule'
  tag stig_id: 'JAMF-10-200040'
  tag gtitle: 'PP-MDM-431007'
  tag fix_id: 'F-105277r2_fix'
  tag satisfies: ['SRG-APP-000148']
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
