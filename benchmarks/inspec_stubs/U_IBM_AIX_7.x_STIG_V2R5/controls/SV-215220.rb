control 'SV-215220' do
  title 'AIX must require the change of at least 50% of the total number of characters when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up.  For example, a password length of 15 characters must require the change of at least 8 characters.'
  desc 'check', %q(From the command prompt, run the following command to check the system default "mindiff" attribute value:
# lssec -f /etc/security/user -s default -a mindiff
default mindiff=8

If the default "mindiff" value is not set, or its value is less than "8", this is a finding.

From the command prompt, run the following command to check "mindiff" attribute value for all accounts:
# lsuser -a mindiff ALL
root  mindiff=9
user1 mindiff=8
user2 mindiff=8
user3 mindiff=10

If any user's "mindiff" value is less than "8", this is a finding.)
  desc 'fix', 'From the command prompt, run the following command to set "mindiff=8" (assume that the password is at least 15-character long) for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a mindiff=8

For each user who has "mindiff" value less than "8", set its "mindiff" value to "8" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a mindiff=8'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16418r294111_chk'
  tag severity: 'high'
  tag gid: 'V-215220'
  tag rid: 'SV-215220r508663_rule'
  tag stig_id: 'AIX7-00-001123'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-16416r294112_fix'
  tag 'documentable'
  tag legacy: ['V-91287', 'SV-101385']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
