control 'SV-251412' do
  title 'The Ivanti MobileIron Core server must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

'
  desc 'check', 'Verify the local user account uses at least one special character:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Verify "Special" is checked.

 If "Special" is not checked, this is a finding.'
  desc 'fix', 'Configure a password with at least one special character:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Check "Special".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54847r806366_chk'
  tag severity: 'medium'
  tag gid: 'V-251412'
  tag rid: 'SV-251412r806368_rule'
  tag stig_id: 'IMIC-11-005300'
  tag gtitle: 'SRG-APP-000169-UEM-000099'
  tag fix_id: 'F-54800r806367_fix'
  tag satisfies: ['FMT_SMF.1(2)b \nReference: PP-MDM-431022']
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
