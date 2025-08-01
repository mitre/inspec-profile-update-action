control 'SV-218646' do
  title 'The /etc/smbpasswd file must not have an extended ACL.'
  desc 'If the permissions of the "smbpasswd" file are too permissive, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', "Check the permissions of the Samba password files.

Procedure:
# ls -lL /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20121r556136_chk'
  tag severity: 'medium'
  tag gid: 'V-218646'
  tag rid: 'SV-218646r603259_rule'
  tag stig_id: 'GEN006210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20119r556137_fix'
  tag 'documentable'
  tag legacy: ['V-22498', 'SV-64061']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
