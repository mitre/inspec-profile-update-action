control 'SV-840' do
  title 'The ftpusers file must exist.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If this file does not exist, then unauthorized accounts can utilize FTP.'
  desc 'check', "Check the system for an ftpusers file. If no ftpusers file appropriate for the system's FTP service exists, this is a finding."
  desc 'fix', "Create an ftpusers file appropriate for the system's FTP service."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-707r2_chk'
  tag severity: 'medium'
  tag gid: 'V-840'
  tag rid: 'SV-840r2_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'GEN004880'
  tag fix_id: 'F-994r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
