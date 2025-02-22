control 'SV-12512' do
  title 'All FTP users must have a default umask of 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask is stored as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Check the umask setting for the FTP user.

Procedure:
# su - ftp
$ umask

If the umask value does not return 077, this is a finding.'
  desc 'fix', 'Edit the initialization files for the FTP user and set the umask to 077.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7976r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12011'
  tag rid: 'SV-12512r2_rule'
  tag stig_id: 'GEN005040'
  tag gtitle: 'GEN005040'
  tag fix_id: 'F-11272r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
