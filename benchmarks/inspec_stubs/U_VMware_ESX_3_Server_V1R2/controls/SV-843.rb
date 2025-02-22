control 'SV-843' do
  title 'The ftpusers file must have mode 0640 or less permissive.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification.  Unauthorized modification could result in Denial-of-Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', 'Check the permissions of the ftpusers file.  If the ftpusers file has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the ftpusers file to 0640.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8064r2_chk'
  tag severity: 'medium'
  tag gid: 'V-843'
  tag rid: 'SV-843r2_rule'
  tag stig_id: 'GEN004940'
  tag gtitle: 'GEN004940'
  tag fix_id: 'F-997r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
