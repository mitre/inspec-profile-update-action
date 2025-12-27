control 'SV-223503' do
  title 'ACF2 PSWD GSO record value must be set to require at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF to enter ACF2 Command shell
enter SET CONTROL(GSO)

LIST PSWD

If "NOPSWDLC" is listed, this is a finding.'
  desc 'fix', 'Configure the GSO option "PSWDLC" to "YES".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25176r858859_chk'
  tag severity: 'medium'
  tag gid: 'V-223503'
  tag rid: 'SV-223503r861169_rule'
  tag stig_id: 'ACF2-ES-000860'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-25164r500643_fix'
  tag 'documentable'
  tag legacy: ['SV-106811', 'V-97707']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
