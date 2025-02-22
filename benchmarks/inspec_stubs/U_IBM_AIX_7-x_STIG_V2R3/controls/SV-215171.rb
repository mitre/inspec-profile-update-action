control 'SV-215171' do
  title 'AIX must enforce the limit of three consecutive invalid login attempts by a user before the user account is locked and released by an administrator.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'From the command prompt, execute the following command to check the system default value for the maximum number of tries before the system will lock the account:
# lssec -f /etc/security/user -s default -a loginretries

The above command should yield the following output:
default loginretries=0

If the default value is "0" or greater than "3", this is a finding.

From the command prompt, execute the following command to check all active accounts on the system for the maximum number of tries before the system will lock the account:
# lsuser -a loginretries ALL | more

The above command should yield the following output:
root loginretries=3
user1 loginretries=2

If a user has values set to "0" or greater than "3", this is a finding.'
  desc 'fix', 'From the command prompt, execute the following command to configure the number of unsuccessful logins resulting in account lockout for "default:" stanza in "/etc/security/user" file:
# chsec -f /etc/security/user -s default -a loginretries=3 

From the command prompt, execute the following command to configure the number of unsuccessful logins resulting in account lockout for all users who have loginretries values that are 0 or greater than 3:
# chsec -f /etc/security/user -s [user_name] -a loginretries=3'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16369r293964_chk'
  tag severity: 'medium'
  tag gid: 'V-215171'
  tag rid: 'SV-215171r508663_rule'
  tag stig_id: 'AIX7-00-001003'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-16367r293965_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag legacy: ['SV-101319', 'V-91219']
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
