control 'SV-223501' do
  title 'ACF2 PSWD GSO record value must be set to require at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF to enter ACF2 Command shell
enter 
SET CONTROL(GSO)
LIST PSWD
If  NOPSWDUC is listed, this is a finding.'
  desc 'fix', 'Configure the GSO option "PSWDUC" to "YES".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25174r695425_chk'
  tag severity: 'medium'
  tag gid: 'V-223501'
  tag rid: 'SV-223501r695426_rule'
  tag stig_id: 'ACF2-ES-000840'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-25162r500637_fix'
  tag 'documentable'
  tag legacy: ['SV-106807', 'V-97703']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
