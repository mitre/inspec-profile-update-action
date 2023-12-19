control 'SV-215219' do
  title 'AIX must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', %q(From the command prompt, run the following command to check the system default "mindigit" attribute value:
# lssec -f /etc/security/user -s default -a mindigit
default mindigit=1

If the default "mindigit" value is not set, or its value is less than "1", this is a finding.

From the command prompt, run the following command to check mindigit attribute value for all accounts:
# lsuser -a mindigit ALL
root mindigit=1
user2 mindigit=2

If any user's "mindigit" value is less than "1", this is a finding.)
  desc 'fix', 'From the command prompt, run the following command to set "mindigit=1" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a mindigit=1

For each user who has "mindigit=0" set its "mindigit" to "1" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a mindigit=1'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16417r294108_chk'
  tag severity: 'high'
  tag gid: 'V-215219'
  tag rid: 'SV-215219r508663_rule'
  tag stig_id: 'AIX7-00-001122'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-16415r294109_fix'
  tag 'documentable'
  tag legacy: ['SV-101383', 'V-91285']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
