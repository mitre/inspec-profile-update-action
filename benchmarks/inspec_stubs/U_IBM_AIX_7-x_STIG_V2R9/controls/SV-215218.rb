control 'SV-215218' do
  title 'AIX must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', %q(From the command prompt, run the following command to check the system default "minloweralpha" attribute value:
# lssec -f /etc/security/user -s default -a minloweralpha
default minloweralpha=1

If the "default minloweralpha" value is not set, or its value is less than "1", this is a finding.

From the command prompt, run the following command to check "minloweralpha" attribute value for all accounts:
# lsuser -a minloweralpha ALL
root minloweralpha=1
user2 minloweralpha=2
user3 minloweralpha=1

If any user's "minloweralpha" value is less than "1", this is a finding.)
  desc 'fix', 'From the command prompt, run the following command to set "minloweralpha=1" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a minloweralpha=1

For each user who has "minloweralpha=0" set its "minloweralpha" to "1" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a minloweralpha=1'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16416r294105_chk'
  tag severity: 'high'
  tag gid: 'V-215218'
  tag rid: 'SV-215218r508663_rule'
  tag stig_id: 'AIX7-00-001121'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-16414r294106_fix'
  tag 'documentable'
  tag legacy: ['SV-101381', 'V-91283']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
