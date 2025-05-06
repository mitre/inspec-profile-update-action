control 'SV-39820' do
  title 'The root account must be the only account having an UID of 0.'
  desc 'If an account has an UID of 0, it has root authority. Multiple accounts with an UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-773'
  tag rid: 'SV-39820r1_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'GEN000880'
  tag fix_id: 'F-24403r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, IAIA-2, IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
