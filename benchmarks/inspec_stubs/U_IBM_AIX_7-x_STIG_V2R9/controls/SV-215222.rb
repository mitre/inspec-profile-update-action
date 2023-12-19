control 'SV-215222' do
  title 'AIX Operating systems must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(From the command prompt, run the following command to check the system default "minage" attribute value:
# lssec -f /etc/security/user -s default -a minage
default minage=1

If the default "minage" value is not set, or its value is less than "1", this is a finding.

From the command prompt, run the following command to check "minage" attribute value for all accounts:
# lsuser -a minage ALL
root  minage=1
user1 minage=1
user2 minage=2

If any user's "minage" value is less than "1", this is a finding.)
  desc 'fix', 'From the command prompt, run the following command to set "minage=1" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a minage=1

For each user who has "minage=0" set its "minage" to "1" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a minage=1'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16420r294117_chk'
  tag severity: 'medium'
  tag gid: 'V-215222'
  tag rid: 'SV-215222r508663_rule'
  tag stig_id: 'AIX7-00-001125'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-16418r294118_fix'
  tag 'documentable'
  tag legacy: ['V-91309', 'SV-101407']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
