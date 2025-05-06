control 'SV-85131' do
  title 'The storage system must require passwords contain a minimum of 15 characters, after an administrator has set the minimum password length to that value.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify that the minimum password length is set to a value of "15". Check the current password configuration:

cli% setpassword -minlen 15

If an error is reported, this is a finding.

Note: You must have super-admin privileges to perform this action.'
  desc 'fix', 'Configure the minimum password length for a value of "15" using the following command:

cli% setpassword -minlen 15

Note: You must have super-admin privileges to perform this action.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70509'
  tag rid: 'SV-85131r1_rule'
  tag stig_id: 'HP3P-32-001525'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-76747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
