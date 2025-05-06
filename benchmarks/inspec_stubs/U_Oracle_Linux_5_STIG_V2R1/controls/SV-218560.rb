control 'SV-218560' do
  title 'The ftpusers file must be group-owned by root, bin, sys, or system.'
  desc 'If the ftpusers file is not group-owned by root or a system group, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the group ownership of the ftpusers file.

Procedure:
# ls -lL /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the ftpusers file.

Procedure:
# chgrp root /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20035r562774_chk'
  tag severity: 'medium'
  tag gid: 'V-218560'
  tag rid: 'SV-218560r603259_rule'
  tag stig_id: 'GEN004930'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20033r562775_fix'
  tag 'documentable'
  tag legacy: ['V-22444', 'SV-63015']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
