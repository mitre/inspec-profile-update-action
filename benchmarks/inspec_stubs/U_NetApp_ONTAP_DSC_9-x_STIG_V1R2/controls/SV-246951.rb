control 'SV-246951' do
  title 'ONTAP must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Use "security login role config show -role admin -fields passwd-minlength" to see the minimum password length for the role admin.

If ONTAP is not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the minimum password length for the role admin to 15 with "security login role config modify -role admin -passwd-minlength 15".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50383r835255_chk'
  tag severity: 'medium'
  tag gid: 'V-246951'
  tag rid: 'SV-246951r835256_rule'
  tag stig_id: 'NAOT-IA-000005'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-50337r769184_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
