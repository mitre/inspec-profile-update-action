control 'SV-215217' do
  title 'AIX must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', %q(From the command prompt, run the following command to check the system default "minupperalpha" attribute value:
# lssec -f /etc/security/user -s default -a minupperalpha

The above command should yield the following output:
default minupperalpha=1

If the default "minupperalpha" value is not set, or its value is less than "1", this is a finding.

From the command prompt, run the following command to check "minupperalpha" attribute value for all accounts:
# lsuser -a minupperalpha ALL

The above command should yield the following output:
root minupperalpha=2
user2 minupperalpha=2
user3 minupperalpha=1

If any user's "minupperalpha" value is less than "1", this is a finding.)
  desc 'fix', 'From the command prompt, run the following command to set "minupperalpha=1" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a minupperalpha=1

For each user who has "minupperalpha=0", set its "minupperalpha" to "1" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a minupperalpha=1'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16415r294102_chk'
  tag severity: 'high'
  tag gid: 'V-215217'
  tag rid: 'SV-215217r508663_rule'
  tag stig_id: 'AIX7-00-001120'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-16413r294103_fix'
  tag 'documentable'
  tag legacy: ['V-91281', 'SV-101379']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
