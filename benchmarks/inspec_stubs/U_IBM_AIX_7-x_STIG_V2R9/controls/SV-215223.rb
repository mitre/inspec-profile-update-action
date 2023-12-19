control 'SV-215223' do
  title 'AIX Operating systems must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'From the command prompt, run the following command to check the system default "maxage" attribute value:
# lssec -f /etc/security/user -s default -a maxage
default maxage=8

If the default "maxage" value is not set, or its value is great than "8", or its value is set to "0", this is a finding.

From the command prompt, run the following command to check "maxage" attribute value for all accounts:
# lsuser -a maxage ALL
root maxage=8
user1 maxage=8
user2 maxage=8

If any user does not have "maxage" set, or its "maxage" value is greater than "8", or its value is set to "0", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "maxage=8" (56 days) for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a maxage=8

For each user who has "maxage" value great than "8", set its "maxage" to "8" by running the following command from command prompt:
# chsec -f /etc/security/user -s [user_name] -a maxage=8'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16421r294120_chk'
  tag severity: 'medium'
  tag gid: 'V-215223'
  tag rid: 'SV-215223r508663_rule'
  tag stig_id: 'AIX7-00-001126'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-16419r294121_fix'
  tag 'documentable'
  tag legacy: ['SV-101409', 'V-91311']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
