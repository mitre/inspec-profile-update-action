control 'SV-251346' do
  title 'The organization must establish weekly data backup procedures for the network Intrusion Detection and Prevention System (IDPS) data.'
  desc 'IDPS data needs to be backed up to ensure preservation in the case a loss of data due to hardware failure or malicious activity.'
  desc 'check', 'Interview the SA to determine the IDPS backup procedures as well as have SA display the backup files saved on the file server.

If the IDPS data is not backed up on a weekly basis, this is a finding.'
  desc 'fix', 'The organization must establish weekly backup procedures for the network IDS/IPS data.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54781r805991_chk'
  tag severity: 'medium'
  tag gid: 'V-251346'
  tag rid: 'SV-251346r805993_rule'
  tag stig_id: 'NET-IDPS-033'
  tag gtitle: 'NET-IDPS-033'
  tag fix_id: 'F-54734r805992_fix'
  tag 'documentable'
  tag legacy: ['V-8078', 'SV-8564']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
