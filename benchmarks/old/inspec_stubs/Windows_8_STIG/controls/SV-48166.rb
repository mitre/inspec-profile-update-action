control 'SV-48166' do
  title 'Administrator passwords must be changed as required.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Passwords for the default and emergency administrator accounts must be changed at least annually or when any member of the administrative team leaves the organization.'
  desc 'check', 'Determine if the site has a policy that requires the default and emergency admin passwords to be changed at least annually or when any member of the administrative team leaves the organization.  If there is no policy, this is a finding.'
  desc 'fix', 'Define a policy that requires the default and emergency administrator passwords to be changed at least annually or when any member of the administrative team leaves the organization.   Ensure the policy is implemented.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44866r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14225'
  tag rid: 'SV-48166r1_rule'
  tag stig_id: 'WN08-00-000009'
  tag gtitle: 'Administrator Account Password Changes'
  tag fix_id: 'F-41304r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
