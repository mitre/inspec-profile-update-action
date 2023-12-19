control 'SV-215337' do
  title 'AIX must enforce a delay of at least 4 seconds between login prompts following a failed login attempt.'
  desc 'Limiting the number of login attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'From the command prompt, run the following command to check the default "logindelay" value:
# lssec -f /etc/security/login.cfg -s default -a logindelay

The above command should yield the following output:
default logindelay=4

If the above command displays the "logindelay" value less than "4", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "logindelay=4" for the default stanza in "/etc/security/login.cfg":
# chsec -f /etc/security/login.cfg -s default -a logindelay=4'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16535r294462_chk'
  tag severity: 'medium'
  tag gid: 'V-215337'
  tag rid: 'SV-215337r508663_rule'
  tag stig_id: 'AIX7-00-003029'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-16533r294463_fix'
  tag 'documentable'
  tag legacy: ['SV-101667', 'V-91569']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
