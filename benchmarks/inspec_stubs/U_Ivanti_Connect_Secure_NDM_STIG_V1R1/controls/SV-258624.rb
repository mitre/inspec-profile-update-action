control 'SV-258624' do
  title 'The ICS must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Under the section "Account Lockout", verify "Enable Account Lockout for users" is checked.
2. Under the section "Account Lockout", verify "Maximum wrong password attempts" is set to "3".
3. Under the section "Account Lockout", verify "Account Lockout Period in Minutes" is set to "15".

If the ICS must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Under the section "Account Lockout", check the box for "Enable Account Lockout for users".
2. Under the section "Account Lockout", set the box "Maximum wrong password attempts" to "3".
3. Under the section "Account Lockout", set the box "Account Lockout Period in Minutes" to "15".
4. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62364r930558_chk'
  tag severity: 'medium'
  tag gid: 'V-258624'
  tag rid: 'SV-258624r930560_rule'
  tag stig_id: 'IVCS-NM-000720'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-62273r930559_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
