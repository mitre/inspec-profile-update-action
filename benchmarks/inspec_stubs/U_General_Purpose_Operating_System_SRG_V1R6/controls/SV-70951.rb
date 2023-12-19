control 'SV-70951' do
  title 'The operating system must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the operating system enforces password complexity by requiring that at least one lower-case character be used. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one lower-case character be used.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56691'
  tag rid: 'SV-70951r1_rule'
  tag stig_id: 'SRG-OS-000070-GPOS-00038'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-61587r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
