control 'SV-223506' do
  title 'ACF2 PSWD GSO record value must be set to require a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If "PSWDMAX" is set to "60", this is not a finding.'
  desc 'fix', 'Configure Password option "PSWDMAX" to "60" days.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25179r695436_chk'
  tag severity: 'medium'
  tag gid: 'V-223506'
  tag rid: 'SV-223506r695437_rule'
  tag stig_id: 'ACF2-ES-000890'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-25167r500652_fix'
  tag 'documentable'
  tag legacy: ['V-97715', 'SV-106819']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
