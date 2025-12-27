control 'SV-80129' do
  title 'The MaaS360 Server must leverage the MDM Platform user accounts and groups for MaaS360 Server user identification and authentication.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MaaS360 Server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels.  These objectives are best achieved by configuring the MaaS360 Server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory, Kerberos).

SFR ID: FIA'
  desc 'check', 'Review the MaaS360 server console  and confirm that the MDM platform accounts are leveraged when users identify and authenticate themselves to the MaaS360 console.

On the MaaS360 Console complete the following steps:
1. Navigate to Setup >> Login Settings
2. Verify "Configure Federated Single Sign-On" is checked and "Authenticate against Corporate User Directory" is selected
3. For SaaS deployments only verify the Cloud Extender is installed: Setup >> Cloud Extender and verify "Cloud Extender Online" is checked.

If "Configure Federated Single Sign-On" and "Authenticate against Corporate User Directory" are not selected, this is a finding.

For SaaS deployments if Cloud Extender is not installed or "Cloud Extender Online" is not checked, this is a finding.'
  desc 'fix', 'Configure the MaaS360 Server to leverage the MDM Platform user accounts and groups for MaaS360 Server user identification and authentication.

On the MaaS360 Console complete the following steps:
1. Navigate to Setup >> Login Settings
2. Select "Configure Federated Single Sign-On" and "Authenticate against Corporate User Directory"
3. For SaaS deployments only install the Cloud Extender: Setup >> Cloud Extender and select "Cloud Extender Online"'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66199r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65639'
  tag rid: 'SV-80129r1_rule'
  tag stig_id: 'M360-01-005300'
  tag gtitle: 'PP-MDM-204101'
  tag fix_id: 'F-71567r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
