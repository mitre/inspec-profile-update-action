control 'SV-213328' do
  title 'The Solidcore client Command Line Interface (CLI) Access Password must be changed from the default.'
  desc 'The Solidcore client can be configured locally at the CLI, but only when accessed with the required password.

Since the McAfee Application Control configuration is to be managed by ePO policies, allowing enablement of the CLI to would introduce the capability of local configuration changes. 

Strict management of the accessibility of the CLI is necessary in order to prevent its misuse.

The misuse of the CLI would open the system up to the possible configuration changes potentially allowing malicious applications to execute unknowingly.'
  desc 'check', 'This is a manual procedure to verify the CLI Access Password has been changed from its default setting by the ePO administrator. 

Ask the ePO admin, "Has the CLI Access Password been changed from its default setting?"

If the default password is being used, this is a finding. 

Note: The password does not need to be divulged during the review. An interview question of the SA to validate that it is not the default is sufficient.'
  desc 'fix', %q(Change the CLI password with one other than the default, using administrative password complexity.

From the ePO server console System Tree, select "My Organization".

In the "Configuration (Client)" category, click on the Organization's specific Configuration (Client) McAfee Default policy.

In the "CLI" tab, type a password other than the default, ensuring to conform to password complexity.

Confirm the password.

Click "Save".)
  impact 0.7
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14556r309081_chk'
  tag severity: 'high'
  tag gid: 'V-213328'
  tag rid: 'SV-213328r506897_rule'
  tag stig_id: 'MCAC-TE-000102'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14554r309082_fix'
  tag 'documentable'
  tag legacy: ['V-74213', 'SV-88887']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
