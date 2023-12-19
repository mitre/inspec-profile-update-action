control 'SV-46137' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43396r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1059'
  tag rid: 'SV-46137r1_rule'
  tag stig_id: 'GEN006200'
  tag gtitle: 'GEN006200'
  tag fix_id: 'F-39479r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
