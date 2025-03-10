control 'SV-221650' do
  title 'All Workspace ONE UEM server local accounts created during application installation and configuration must be disabled or removed.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

'
  desc 'check', 'Review the configuration for Workspace ONE UEM server administrative accounts for any local accounts:

1. Log in to the Workspace ONE UEM Administration console.
2. Choose Accounts >> Administrators >> List View.
3. Review user types under the Admin Type heading. If any users have an Admin Type of "Basic", this is a finding.

Exception: One local "Emergency" account may remain.'
  desc 'fix', 'Configure the Workspace ONE UEM server to remove any local accounts created during installation and configuration.

Exception: One local "Emergency" account may remain.

1. Log in to the Workspace ONE UEM Administration console.
2. Choose Accounts >> Administrators >> List View.
3. Review user types under the Admin Type heading, and select all users, and only users with an Admin Type of "Basic". Do NOT select users with an Admin Type of "Directory". Selecting one or more users with the "Basic" Admin Type will cause the "More Actions" drop-down to appear.
4. From the More Actions drop down select "Delete". This will result in an "Are you sure you want to delete this record?" pop-up box asking to confirm deletion of the selected account(s).
5. Click "OK" to delete the selected accounts.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23365r805069_chk'
  tag severity: 'medium'
  tag gid: 'V-221650'
  tag rid: 'SV-221650r805071_rule'
  tag stig_id: 'VMW1-00-200040'
  tag gtitle: 'PP-MDM-431007'
  tag fix_id: 'F-23354r805070_fix'
  tag satisfies: ['SRG-APP-000148\nSFR ID: FMT_SMF.1.1(2) b / IA-5(1)(a)']
  tag 'documentable'
  tag legacy: ['SV-111299', 'V-102343']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
