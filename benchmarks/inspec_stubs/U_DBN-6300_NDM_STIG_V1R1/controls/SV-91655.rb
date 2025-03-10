control 'SV-91655' do
  title 'The DBN-6300 must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

Since the device cannot be configured for password complexity, not having a strong password can result in the success of a brute force attack, which would give immediate access to a privileged system.'
  desc 'check', 'Verify the minimum password length is set to "15".

Navigate to Settings >> Initial Configuration >> Authentication.

If the "Minimum User Password Length" is not set to "15", this is a finding.'
  desc 'fix', 'Configure the minimum password length to "15".

Navigate to Settings >> Initial Configuration >> Authentication.

Enter "15" in the "Minimum User Password Length".

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76959'
  tag rid: 'SV-91655r1_rule'
  tag stig_id: 'DBNW-DM-000055'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-83655r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
