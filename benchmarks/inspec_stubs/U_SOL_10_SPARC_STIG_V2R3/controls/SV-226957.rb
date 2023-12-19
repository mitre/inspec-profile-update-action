control 'SV-226957' do
  title 'All FTP users must have a default umask of 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask is stored as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Check the umask setting for the FTP user.

Procedure:
# su - ftp
$ umask

If the umask value does not return 077, this is a finding.'
  desc 'fix', 'Edit the initialization files for the FTP user and set the umask to 077.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29119r485198_chk'
  tag severity: 'medium'
  tag gid: 'V-226957'
  tag rid: 'SV-226957r603265_rule'
  tag stig_id: 'GEN005040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29107r485199_fix'
  tag 'documentable'
  tag legacy: ['SV-12512', 'V-12011']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
