control 'SV-215227' do
  title 'AIX must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Run the following command to check the system default value for "minspecialchar" attribute:
# lssec -f /etc/security/user -s default -a minspecialchar

The above command should yield the following output:
default minspecialchar=1

If the default value is "0", or the default value is empty, this is a finding.

From the command prompt, run the following command to check "minspecialchar" attribute value for all accounts:
# lsuser -a minspecialchar ALL

The above command should yield the following output:
root minspecialchar=1
user1 minspecialchar=1
user2 minspecialchar=2
user3 minspecialchar=1

If any account has "minspecialchar=0", or the "minspecialchar" value is not set, this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "minspecialchar=1" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a minspecialchar=1

Run the following command to re-check "minspecialchar" values for all users:
# lsuser -a minspecialchar ALL

For each user who has "minspecialchar=0", set its "minspecialchar" to "1" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a minspecialchar=1'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16425r808441_chk'
  tag severity: 'medium'
  tag gid: 'V-215227'
  tag rid: 'SV-215227r808442_rule'
  tag stig_id: 'AIX7-00-001130'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-16423r294133_fix'
  tag 'documentable'
  tag legacy: ['V-91485', 'SV-101583']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
