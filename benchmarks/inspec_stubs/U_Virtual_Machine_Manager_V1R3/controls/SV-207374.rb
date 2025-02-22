control 'SV-207374' do
  title 'The VMM must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the VMM enforces password complexity by requiring that at least one numeric character be used.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce password complexity by requiring that at least one numeric character be used.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7631r365532_chk'
  tag severity: 'medium'
  tag gid: 'V-207374'
  tag rid: 'SV-207374r378745_rule'
  tag stig_id: 'SRG-OS-000071-VMM-000380'
  tag gtitle: 'SRG-OS-000071'
  tag fix_id: 'F-7631r365533_fix'
  tag 'documentable'
  tag legacy: ['SV-71229', 'V-56969']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
