control 'SV-251779' do
  title 'The NSX-T Manager must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'From an NSX-T Manager shell, run the following command(s):

>  get auth-policy api lockout-reset-period

Expected result:
900 seconds

If the output does not match the expected result, this is a finding.

>  get auth-policy api lockout-period

Expected result:
900 seconds

If the output does not match the expected result, this is a finding.

>  get auth-policy api max-auth-failures

Expected result:
3

If the output does not match the expected result, this is a finding.

>  get auth-policy cli lockout-period

Expected result:
900 seconds

If the output does not match the expected result, this is a finding.

>  get auth-policy cli max-auth-failures

Expected result:
3

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an NSX-T Manager shell, run the following command(s):

> set auth-policy api lockout-reset-period 900
> set auth-policy api lockout-period 900
> set auth-policy api max-auth-failures 3
> set auth-policy cli lockout-period 900
> set auth-policy cli max-auth-failures 3'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Manager NDM'
  tag check_id: 'C-55239r810338_chk'
  tag severity: 'medium'
  tag gid: 'V-251779'
  tag rid: 'SV-251779r810340_rule'
  tag stig_id: 'TNDM-3X-000012'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-55193r810339_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
