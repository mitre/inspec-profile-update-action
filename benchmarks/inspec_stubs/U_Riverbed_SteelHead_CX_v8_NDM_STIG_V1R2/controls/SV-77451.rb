control 'SV-77451' do
  title 'Riverbed Optimization System (RiOS) must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify that RiOS is configured to enforce a minimum 15-character password length.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Verify that "Minimum Password Length:" is set to "15"

If "Minimum Password Length:" is not set to "15", this is a finding.'
  desc 'fix', 'Configure RiOS to enforce a minimum 15-character password length.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Set the value of "Minimum Password Length:" to "15"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63713r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62961'
  tag rid: 'SV-77451r1_rule'
  tag stig_id: 'RICX-DM-000114'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-68879r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
