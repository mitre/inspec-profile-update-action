control 'SV-37538' do
  title 'The ftpusers file must be group-owned by root, bin, sys, or system.'
  desc 'If the ftpusers file is not group-owned by root or a system group, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'fix', 'Change the group owner of the ftpusers file.

Procedure:
# chgrp root /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22444'
  tag rid: 'SV-37538r1_rule'
  tag stig_id: 'GEN004930'
  tag gtitle: 'GEN004930'
  tag fix_id: 'F-31454r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
