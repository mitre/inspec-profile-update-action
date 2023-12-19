control 'SV-29266' do
  title 'The system is not configured to use the Classic security model.'
  desc 'Windows includes two network-sharing security models - Classic and Guest only. With the classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Sharing and security model for local accounts” to “Classic - local users authenticate as themselves”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3378'
  tag rid: 'SV-29266r1_rule'
  tag gtitle: 'Sharing and Security Model for Local Accounts'
  tag fix_id: 'F-134r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
