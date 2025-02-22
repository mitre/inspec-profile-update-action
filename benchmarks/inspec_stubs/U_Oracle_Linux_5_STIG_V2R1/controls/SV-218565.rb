control 'SV-218565' do
  title 'All FTP users must have a default umask of 077.'
  desc 'The umask controls the default access mode assigned to newly created files. An umask of 077 limits new files to mode 700 or less permissive. Although umask is stored as a 4-digit number, the first digit representing special access modes is typically ignored or required to be zero (0).'
  desc 'check', 'Check the umask setting for FTP users.

Procedure:
For gssftp:
Assuming an anonymous ftp user has been defined with no user initialization script invoked to change the umask

# ftp localhost
Name: (localhost:root): anonymous
Password: anything
ftp>umask

If the umask value returned is not 077, this is a finding.
or:
# grep "server_args" /etc/xinetd.d/gssftp

The default umask for FTP is "023" if the server _args entry does not contain "-u 077" this is a finding.

For vsftp:
# grep "_mask" /etc/vsftpd/vsftpd.conf
The default "local_umask" setting is 077. If this has been changed, or the "anon_umask" setting is not 077, this is a finding.'
  desc 'fix', 'Edit the initialization files for the ftp user and set the umask to 077.

Procedure:

For gssftp:
Modify the /etc/xinetd.d/gssftp file adding "-u 077" to the server_args entry.

For vsftp:
Modify the "/etc/vsftpd/vsftpd.conf" setting "local_umask" and "anon_umask" to 077.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20040r562789_chk'
  tag severity: 'medium'
  tag gid: 'V-218565'
  tag rid: 'SV-218565r603259_rule'
  tag stig_id: 'GEN005040'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20038r562790_fix'
  tag 'documentable'
  tag legacy: ['V-12011', 'SV-63113']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
