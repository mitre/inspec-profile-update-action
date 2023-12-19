control 'SV-77457' do
  title 'Riverbed Optimization System (RiOS) must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify that RiOS is configured to enforce password complexity that requires at least one numeric character.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Verify that "Minimum Numerical Characters:" is set to "1"

If "Minimum Numerical Characters:" is not set to "1", this is a finding.'
  desc 'fix', 'Configure RiOS to enforce a password complexity that requires at least one numerical character.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Set the value of "Minimum Numerical Characters:" to "1"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62967'
  tag rid: 'SV-77457r1_rule'
  tag stig_id: 'RICX-DM-000117'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-68885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
