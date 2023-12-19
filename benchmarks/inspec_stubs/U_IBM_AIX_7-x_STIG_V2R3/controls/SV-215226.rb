control 'SV-215226' do
  title 'AIX must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From the command prompt, run the following command to check the system default "minlen" attribute value:
# lssec -f /etc/security/user -s default -a minlen
default minlen=15

If the default "minlen" value is not set, or its value is less than "15", this is a finding.

From the command prompt, run the following command to check "minlen" attribute value for all accounts:
# lsuser -a minlen ALL
root minlen=15
user1 minlen=20
user2 minlen=15
user3 minlen=15

If any users have "minlen" value less than "15", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "minlen=15" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a minlen=15

For each user who has "minlen" value less than "15", set its "minlen" to "15" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a minlen=15'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16424r294129_chk'
  tag severity: 'high'
  tag gid: 'V-215226'
  tag rid: 'SV-215226r508663_rule'
  tag stig_id: 'AIX7-00-001129'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-16422r294130_fix'
  tag 'documentable'
  tag legacy: ['V-91317', 'SV-101415']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
