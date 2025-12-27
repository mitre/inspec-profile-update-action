control 'SV-215229' do
  title 'AIX must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', %q(From the command prompt, run the following command to check if the default "dictionlist" attribute is set:
# lssec -f /etc/security/user -s default -a dictionlist

The above command should yield the following output:
dictionlist="/etc/security/ice/dictionary/English"

If the above command shows an empty string for default "dictionlist" attribute, this is a finding.

From the command prompt, run the following command to check if "dictionlist" attribute is set for all users:
# lsuser -a dictionlist ALL

The above command should yield the following output:
root dictionlist=/etc/security/ice/dictionary/English
daemon dictionlist=/etc/security/ice/dictionary/English
bin dictionlist=/etc/security/ice/dictionary/English
sys dictionlist=/etc/security/ice/dictionary/English

If any user's "dictionlist" attribute is empty, this is a finding.)
  desc 'fix', 'From the command prompt, run the following command to set "dictionlist" attribute for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a dictionlist="/etc/security/ice/dictionary/English"

From the command prompt, run the following command to set "dictionlist" attribute for users who have an empty "dictionlist" attribute:
# chsec -f /etc/security/user -s [user_name] -a dictionlist="/etc/security/ice/dictionary/English"'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16427r294138_chk'
  tag severity: 'medium'
  tag gid: 'V-215229'
  tag rid: 'SV-215229r508663_rule'
  tag stig_id: 'AIX7-00-001132'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-16425r294139_fix'
  tag 'documentable'
  tag legacy: ['V-91567', 'SV-101665']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
