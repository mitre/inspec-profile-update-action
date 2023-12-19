control 'SV-96885' do
  title 'Authentication of MaaS360 MDM platform accounts must be configured so they are implemented via an enterprise directory service.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MaaS360 MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MaaS360 MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'Perform the following steps to verify the MaaS360 portal is configured to use an Enterprise directory service for portal access:

Verify the MaaS360 is configured to use the Cloud Extender that connects to the Enterprise authentication service:
1. Log in to the portal.
2. Navigate to "Users" on the menu bar.
3. Select "Directory".
4. Confirm that for every administrator listed, "User Source" has "User Directory (AD)" listed.

If any listed administrator does not have "User Source" as "User Directory (AD)", this is a finding.'
  desc 'fix', 'Install Cloud Extender and configure it to connect to the Enterprise directory service for all portal connections.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82171'
  tag rid: 'SV-96885r1_rule'
  tag stig_id: 'M360-10-007800'
  tag gtitle: 'PP-MDM-314003'
  tag fix_id: 'F-89029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
