control 'SV-29749' do
  title 'Administrator Passwords are changed when necessary.'
  desc 'This check verifies that the passwords for the default and backup administrator accounts are changed at least annually or when any member of the administrative team leaves the organization.'
  desc 'check', 'Interview the SA or IAM to determine if the site has a policy that requires the default and backup admin passwords to be changed at least annually or when any member of the administrative team leaves the organization.'
  desc 'fix', 'Define a policy for required password changes for the default and backup admin account.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14225'
  tag rid: 'SV-29749r1_rule'
  tag gtitle: 'Administrator Account Password Changes'
  tag fix_id: 'F-13549r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
