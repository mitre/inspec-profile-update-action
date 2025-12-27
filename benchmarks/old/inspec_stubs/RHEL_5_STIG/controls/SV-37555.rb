control 'SV-37555' do
  title 'All FTP users must have a default umask of 077.'
  desc 'The umask controls the default access mode assigned to newly created files. An umask of 077 limits new files to mode 700 or less permissive. Although umask is stored as a 4-digit number, the first digit representing special access modes is typically ignored or required to be zero (0).'
  desc 'fix', 'Edit the initialization files for the ftp user and set the umask to 077.

Procedure:

For gssftp:
Modify the /etc/xinetd.d/gssftp file adding "-u 077" to the server_args entry.

For vsftp:
Modify the "/etc/vsftpd/vsftpd.conf" setting "local_umask" and "anon_umask" to 077.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-12011'
  tag rid: 'SV-37555r1_rule'
  tag stig_id: 'GEN005040'
  tag gtitle: 'GEN005040'
  tag fix_id: 'F-31466r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
