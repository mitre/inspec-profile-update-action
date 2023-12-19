control 'SV-96883' do
  title 'The MaaS360 MDM server must be configured to leverage the MDM platform user accounts and groups for MaaS360 MDM server user identification and authentication.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MaaS360 MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MaaS360 MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'Review the MaaS360 server console and confirm that the MDM platform accounts are leveraged when users identify and authenticate themselves to the MaaS360 console.

On the MaaS360 Console, complete the following steps:
1. Navigate to Setup >> Settings.
2. Under Administrator Setting >> Advanced, select "Login Settings".
3. Verify "Configure Federated Single Sign-On" is checked and "Authenticate against Corporate User Directory" is selected.
4. Verify the Cloud Extender is installed: Setup >> Cloud Extender and verify "Cloud Extender Online" is checked.

If "Configure Federated Single Sign-On" and "Authenticate against Corporate User Directory" are not selected, this is a finding.

For SaaS deployments if Cloud Extender is not installed or "Cloud Extender Online" is not checked, this is a finding.'
  desc 'fix', 'Configure the MaaS360 server to leverage the MDM platform user accounts and groups for MaaS360 server user identification and authentication.

On the MaaS360 Console, complete the following steps:
1. Navigate to Setup >> Settings.
2. Under Administrator Setting >> Advanced, select "Login Settings".
3. Select "Configure Federated Single Sign-On" and "Authenticate against Corporate User Directory".
4. Install the Cloud Extender: Setup >> Cloud Extender and select "Cloud Extender Online".'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82169'
  tag rid: 'SV-96883r1_rule'
  tag stig_id: 'M360-10-007700'
  tag gtitle: 'PP-MDM-314002'
  tag fix_id: 'F-89027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
