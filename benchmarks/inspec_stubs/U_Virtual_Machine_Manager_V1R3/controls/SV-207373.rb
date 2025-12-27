control 'SV-207373' do
  title 'The VMM must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the VMM enforces password complexity by requiring that at least one lower-case character be used.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce password complexity by requiring that at least one lower-case character be used.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7630r365529_chk'
  tag severity: 'medium'
  tag gid: 'V-207373'
  tag rid: 'SV-207373r378742_rule'
  tag stig_id: 'SRG-OS-000070-VMM-000370'
  tag gtitle: 'SRG-OS-000070'
  tag fix_id: 'F-7630r365530_fix'
  tag 'documentable'
  tag legacy: ['SV-71193', 'V-56933']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
