control 'SV-29703' do
  title 'Unauthorized shares can be accessed anonymously.'
  desc 'This is a Category 1 finding because the potential for gaining unauthorized system access. Any shares listed can be accessed by any network user.  This could lead to the exposure or corruption of sensitive data.  Enabling this setting is very dangerous.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Shares that can be accessed anonymously” to be defined but containing no entries (Blank).'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-3340'
  tag rid: 'SV-29703r1_rule'
  tag gtitle: 'Anonymous Access to Network Shares'
  tag fix_id: 'F-28819r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
