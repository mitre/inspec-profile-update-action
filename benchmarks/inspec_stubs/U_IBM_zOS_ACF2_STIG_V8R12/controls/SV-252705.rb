control 'SV-252705' do
  title 'The operating system must enforce a minimum 8-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If "MINPSWD" is set to "8", this is not a finding.'
  desc 'fix', 'Configure the Password option "MINPSWD" to "8".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-56161r819058_chk'
  tag severity: 'medium'
  tag gid: 'V-252705'
  tag rid: 'SV-252705r916433_rule'
  tag stig_id: 'ACF2-ES-000990'
  tag gtitle: 'SRG-OS-000481-GPOS-00481'
  tag fix_id: 'F-56111r819059_fix'
  tag 'documentable'
  tag legacy: ['V-97737', 'SV-106841']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
