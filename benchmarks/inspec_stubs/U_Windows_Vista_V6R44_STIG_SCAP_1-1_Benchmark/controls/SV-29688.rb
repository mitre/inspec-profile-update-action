control 'SV-29688' do
  title 'Reversible password encryption is not disabled.'
  desc 'Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords. For this reason, this policy should never be enabled.'
  desc 'fix', 'Configure the system to prevent passwords from being saved using reverse encryption.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-2372'
  tag rid: 'SV-29688r1_rule'
  tag gtitle: 'Reversible Password Encryption'
  tag fix_id: 'F-115r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
