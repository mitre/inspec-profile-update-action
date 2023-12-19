control 'SV-223502' do
  title 'ACF2 PSWD GSO record value must be set to require at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If "PSWDALPH" is coded, this is not a finding.'
  desc 'fix', 'Configure the Password options to include "PSWDALPH".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25175r695427_chk'
  tag severity: 'medium'
  tag gid: 'V-223502'
  tag rid: 'SV-223502r695429_rule'
  tag stig_id: 'ACF2-ES-000850'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-25163r695428_fix'
  tag 'documentable'
  tag legacy: ['SV-106809', 'V-97705']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
