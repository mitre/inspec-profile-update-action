control 'SV-226951' do
  title 'The ftpusers file must be group-owned by root, bin, or sys.'
  desc 'If the ftpusers file is not group-owned by root or a system group, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the group ownership of the ftpusers file.

Procedure:
# ls -lL /etc/ftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the ftpusers file.

Procedure:
# chgrp root /etc/ftpusers'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29113r485180_chk'
  tag severity: 'medium'
  tag gid: 'V-226951'
  tag rid: 'SV-226951r603265_rule'
  tag stig_id: 'GEN004930'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29101r485181_fix'
  tag 'documentable'
  tag legacy: ['V-22444', 'SV-39905']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
