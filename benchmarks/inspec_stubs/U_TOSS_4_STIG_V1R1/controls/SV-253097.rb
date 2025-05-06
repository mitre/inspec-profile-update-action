control 'SV-253097' do
  title 'TOSS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt with the following command:

$ sudo grep -i fail_delay /etc/login.defs

FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.

Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:

FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56550r824961_chk'
  tag severity: 'medium'
  tag gid: 'V-253097'
  tag rid: 'SV-253097r824963_rule'
  tag stig_id: 'TOSS-04-040550'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-56500r824962_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
