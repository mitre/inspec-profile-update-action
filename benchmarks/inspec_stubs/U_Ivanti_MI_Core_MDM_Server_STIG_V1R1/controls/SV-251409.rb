control 'SV-251409' do
  title 'The Ivanti MobileIron Core server must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised. 

'
  desc 'check', 'Verify the local user account uses at least one uppercase character:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Verify "Upper Case" is checked.

 If "Upper Case" is not checked, this is a finding.'
  desc 'fix', 'Configure a password with at least one uppercase character:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Check "Upper Case".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54844r809563_chk'
  tag severity: 'medium'
  tag gid: 'V-251409'
  tag rid: 'SV-251409r806359_rule'
  tag stig_id: 'IMIC-11-005000'
  tag gtitle: 'SRG-APP-000166-UEM-000096'
  tag fix_id: 'F-54797r806358_fix'
  tag satisfies: ['FMT_SMF.1(2)b \nReference: PP-MDM-431020']
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
