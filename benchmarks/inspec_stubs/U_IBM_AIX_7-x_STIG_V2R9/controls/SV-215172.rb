control 'SV-215172' do
  title 'AIX must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.'
  desc 'check', 'From the command prompt, execute the following command to display maxulogs values for all the user account:
# lsuser -a maxulogs ALL

The above command should yield the following output:
root maxulogs=10
user_1 maxulogs=10
  
If the above command shows any user account that does not have the "maxulogs" attribute set, or its value is "0", or its value greater than "10", this is a finding.'
  desc 'fix', 'From the command prompt, execute the following command to set "maxulogs=10" for the "default:" stanza in the "/etc/security/user" file:
# chsec -f /etc/security/user -s default -a maxulogs=10

For each user account whose "maxulogs" value is greater than "10", or their "maxulogs" value is not set,  or the values are set to "0", execute the following command to set "maxulogs=10":
# chuser maxulogs=10 [user_name]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16370r293967_chk'
  tag severity: 'medium'
  tag gid: 'V-215172'
  tag rid: 'SV-215172r877399_rule'
  tag stig_id: 'AIX7-00-001004'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-16368r293968_fix'
  tag 'documentable'
  tag legacy: ['V-91227', 'SV-101327']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
