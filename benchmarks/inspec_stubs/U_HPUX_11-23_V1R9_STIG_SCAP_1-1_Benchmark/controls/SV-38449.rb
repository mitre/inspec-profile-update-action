control 'SV-38449' do
  title 'The root account must be the only account having an UID of 0.'
  desc 'If an account has an UID of 0, it has root authority. Multiple accounts with an UID of 0 afford more opportunity for potential intruders to compromise a privileged account.'
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-773'
  tag rid: 'SV-38449r1_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'GEN000880'
  tag fix_id: 'F-31528r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, ECLP-1, IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
