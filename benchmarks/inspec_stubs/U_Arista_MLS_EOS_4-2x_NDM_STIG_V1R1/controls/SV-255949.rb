control 'SV-255949' do
  title 'The Arista network device must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Verify the Arista device is configured to enforce the limit of three consecutive invalid logon attempts with the following command:

switch#show running-config | section aaa

aaa authentication policy lockout failure 3
duration 900

If the Arista device is not configured to enforce the limit of three consecutive invalid logon attempts, this is a finding.'
  desc 'fix', 'Configure the account lockout policy using the following commands:

switch(config)#aaa authentication policy lockout failure 3
switch(config)#duration 900
switch(config)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59625r882187_chk'
  tag severity: 'medium'
  tag gid: 'V-255949'
  tag rid: 'SV-255949r882189_rule'
  tag stig_id: 'ARST-ND-000120'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-59568r882188_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
