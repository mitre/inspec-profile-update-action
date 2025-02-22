control 'SV-215224' do
  title 'AIX must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'From the command prompt, run the following command to check the system default "histsize" attribute value:
# lssec -f /etc/security/user -s default -a histsize
default histsize=5

If the default "histsize" value is not set, or its value is less than "5", this is a finding.

From the command prompt, run the following command to check "histsize" attribute value for all accounts:
# lsuser -a histsize ALL
root histsize=5
user1 histsize=5
user2 histsize=5
user3 histsize=6

If any user does not have "histsize" set, or its "histsize" value is less than "5", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "histsize=5" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a histsize=5

For each user who has "histsize" value less than "5", set its "histsize" to "5" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a histsize=5'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16422r294123_chk'
  tag severity: 'medium'
  tag gid: 'V-215224'
  tag rid: 'SV-215224r508663_rule'
  tag stig_id: 'AIX7-00-001127'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-16420r294124_fix'
  tag 'documentable'
  tag legacy: ['V-91313', 'SV-101411']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
