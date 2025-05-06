control 'SV-29544' do
  title 'Named Pipes and Shares can be accessed anonymously.'
  desc 'This is a Category 1 finding because of the potential for gaining unauthorized system access. 

Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  

When this setting is disabled, Network shares can be accessed by any network user.  This could lead to the exposure or corruption of sensitive data.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Restrict anonymous access to Named Pipes and Shares” to “Enabled”.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-6834'
  tag rid: 'SV-29544r1_rule'
  tag gtitle: 'Anonymous Access to Named Pipes and Shares'
  tag fix_id: 'F-6521r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
