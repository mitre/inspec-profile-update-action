control 'SV-24999' do
  title 'Administrator passwords must be changed as required.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Passwords for the built-in administrator account and any emergency administrator accounts must be changed at least annually or when any member of the administrative team leaves the organization.'
  desc 'check', 'Determine if the site has a policy that requires passwords for the built-in administrator account and any emergency administrator accounts to be changed at least annually or when any member of the administrative team leaves the organization.  If a policy does not exist or is not enforced, this is a finding.'
  desc 'fix', 'Define and enforce a policy that requires passwords for the built-in administrator account and any emergency administrator accounts to be changed at least annually or when any member of the administrative team leaves the organization.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14225'
  tag rid: 'SV-24999r2_rule'
  tag gtitle: 'Administrator Account Password Changes'
  tag fix_id: 'F-66983r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
