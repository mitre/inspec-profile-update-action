control 'SV-218645' do
  title 'The smbpasswd file must have mode 0600 or less permissive.'
  desc 'If the smbpasswd file has a mode more permissive than 0600, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the mode of files maintained using "smbpasswd".

Procedure:
# ls -lL /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If a "smbpasswd" maintained file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the files maintained through smbpasswd to 0600.

Procedure:
# chmod 0600 /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20120r556133_chk'
  tag severity: 'medium'
  tag gid: 'V-218645'
  tag rid: 'SV-218645r603259_rule'
  tag stig_id: 'GEN006200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20118r556134_fix'
  tag 'documentable'
  tag legacy: ['V-1059', 'SV-64063']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
