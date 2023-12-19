control 'SV-215186' do
  title 'AIX must configure the ttys value for all interactive users.'
  desc %q(A user's "ttys" attribute controls from which device(s) the user can authenticate and log in. If the "ttys" attribute is not specified, all terminals can access the user account.)
  desc 'check', 'Verify that the default "ttys" value is set for all users:

# lssec -f /etc/security/user -s default -a ttys
default ttys=ALL

If the value returned is not "ttys=ALL", this is a finding.

From the command prompt, run the following command to check "ttys" attribute value for all accounts:
# lsuser -a ttys ALL

The above command should yield the following output:
root ttys=ALL
user1 ttys=ALL
user2 ttys=ALL
user3 ttys=ALL

If any interactive user account does not have "ttys=ALL", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "ttys=ALL" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a ttys=ALL

Run the following command to recheck "ttys" values for all users:
# lsuser -a ttys ALL

For each interactive user who does not have "ttys=ALL", set the value of "ttys" to "ALL" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a ttys=ALL'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16384r569508_chk'
  tag severity: 'medium'
  tag gid: 'V-215186'
  tag rid: 'SV-215186r538429_rule'
  tag stig_id: 'AIX7-00-001025'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-16382r569436_fix'
  tag 'documentable'
  tag legacy: ['SV-102347', 'V-92245']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
