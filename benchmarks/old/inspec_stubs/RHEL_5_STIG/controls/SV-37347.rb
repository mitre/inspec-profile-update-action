control 'SV-37347' do
  title 'The root account must be the only account having a UID of 0.'
  desc 'If an account has a UID of 0, it has root authority.  Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-773'
  tag rid: 'SV-37347r2_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'GEN000880'
  tag fix_id: 'F-31283r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
