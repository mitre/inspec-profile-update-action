control 'SV-207372' do
  title 'The VMM must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the VMM enforces password complexity by requiring that at least one upper-case character be used.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce password complexity by requiring that at least one upper-case character be used.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7629r365526_chk'
  tag severity: 'medium'
  tag gid: 'V-207372'
  tag rid: 'SV-207372r378739_rule'
  tag stig_id: 'SRG-OS-000069-VMM-000360'
  tag gtitle: 'SRG-OS-000069'
  tag fix_id: 'F-7629r365527_fix'
  tag 'documentable'
  tag legacy: ['SV-71191', 'V-56931']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
