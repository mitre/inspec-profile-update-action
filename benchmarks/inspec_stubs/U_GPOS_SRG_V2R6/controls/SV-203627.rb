control 'SV-203627' do
  title 'The operating system must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the operating system enforces password complexity by requiring that at least one numeric character be used. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one numeric character be used.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3752r557605_chk'
  tag severity: 'medium'
  tag gid: 'V-203627'
  tag rid: 'SV-203627r557607_rule'
  tag stig_id: 'SRG-OS-000071-GPOS-00039'
  tag gtitle: 'SRG-OS-000071'
  tag fix_id: 'F-3752r557606_fix'
  tag 'documentable'
  tag legacy: ['V-56693', 'SV-70953']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
