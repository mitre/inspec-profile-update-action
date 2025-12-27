control 'SV-234372' do
  title 'The UEM server must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431022'
  desc 'check', 'Verify the UEM server enforces password complexity by requiring that at least one special character be used.

If the UEM server does not enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure the UEM server to enforce password complexity by requiring that at least one special character be used.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37557r614126_chk'
  tag severity: 'medium'
  tag gid: 'V-234372'
  tag rid: 'SV-234372r617355_rule'
  tag stig_id: 'SRG-APP-000169-UEM-000099'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-37522r614127_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
