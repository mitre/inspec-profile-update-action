control 'SV-70949' do
  title 'The operating system must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the operating system enforces password complexity by requiring that at least one upper-case character be used. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one upper-case character be used.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56689'
  tag rid: 'SV-70949r1_rule'
  tag stig_id: 'SRG-OS-000069-GPOS-00037'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-61585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
