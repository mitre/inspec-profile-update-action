control 'SV-251411' do
  title 'The Ivanti MobileIron Core server must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

'
  desc 'check', 'Verify the local user account uses at least one numeric character:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Verify "Numeric" is checked.

 If "Numeric" is not checked, this is a finding.'
  desc 'fix', 'Configure a password with at least one numeric character:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Check "Numeric".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54846r806363_chk'
  tag severity: 'medium'
  tag gid: 'V-251411'
  tag rid: 'SV-251411r806365_rule'
  tag stig_id: 'IMIC-11-005200'
  tag gtitle: 'SRG-APP-000168-UEM-000098'
  tag fix_id: 'F-54799r806364_fix'
  tag satisfies: ['FMT_SMF.1(2)b \nReference: PP-MDM-431021']
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
