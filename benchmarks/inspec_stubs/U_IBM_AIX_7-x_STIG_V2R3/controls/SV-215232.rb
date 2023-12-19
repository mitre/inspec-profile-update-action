control 'SV-215232' do
  title 'AIX must require passwords to contain no more than three consecutive repeating characters.'
  desc 'Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Check system default for "maxrepeats" attribute:
# lssec -f /etc/security/user -s default -a maxrepeats
default maxrepeats=3

If the default "maxrepeats" is greater than "3", or its value is not set, or its value is set to "0", this is a finding.

Check the "maxrepeats" setting for all users using:
# lsuser -a maxrepeats ALL

The above command should yield the following output:
root maxrepeats=3
daemon maxrepeats=3
bin maxrepeats=3
sys maxrepeats=3

If the "maxrepeats" setting for any user is greater than "3", or its value is set to "0", this is a finding.'
  desc 'fix', 'Use the "chsec" command to set "maxrepeats" to "3" for the default stanza:
# chsec -f /etc/security/user -s default -a maxrepeats=3 

Use the "chsec" command to set "maxrepeats" to "3" for all the users who have "maxrepeats" values that are greater than "3", or its value is set to "0":
# chuser maxrepeats=3 [user_name]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16430r294147_chk'
  tag severity: 'medium'
  tag gid: 'V-215232'
  tag rid: 'SV-215232r508663_rule'
  tag stig_id: 'AIX7-00-001136'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16428r294148_fix'
  tag 'documentable'
  tag legacy: ['SV-101765', 'V-91667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
