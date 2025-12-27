control 'SV-29642' do
  title 'Lockout duration does not meet minimum requirements.'
  desc 'This parameter specifies the amount of time that must pass before a locked-out account is automatically unlocked by the system.'
  desc 'fix', 'Configure the system so that the bad logon lockout duration conforms to DoD requirements.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1099'
  tag rid: 'SV-29642r1_rule'
  tag gtitle: 'Lockout Duration'
  tag fix_id: 'F-6571r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
