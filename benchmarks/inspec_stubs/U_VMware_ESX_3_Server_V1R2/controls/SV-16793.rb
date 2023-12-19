control 'SV-16793' do
  title 'The ESX Servers and management servers are not backed up in accordance to the MAC level of the servers.'
  desc 'Backups of the ESX Server and management servers are critical in order to recover from hardware problems, unexpected software errors, or a disaster to the computing facility. Data backup must be performed in accordance with its mission assurance category (MAC) level. For MAC III systems it is necessary to ensure that backups are performed weekly. For MAC II systems backups are performed daily and the recovery media is stored off-site in a protected facility in accordance with its mission assurance category and confidentiality level. In MAC I systems backups are maintained through a redundant secondary system which is not collocated, and can be activated without loss of data or disruption to the operation.'
  desc 'check', '1. Determine the MAC level of the ESX and management servers by asking the IAO/SA.
2. Once the MAC level is determined, locate the backup media or storage location.
    For MAC I servers, a redundant secondary system is required that is not collocated.
    For MAC II servers, daily backups are required with recovery media stored offline.
    For MAC III servers, backups must be performed weekly.
3. Depending on the MAC level, verify the servers are backed up to media or storage within the    
      guidelines of the MAC level.  If they are not, this is a finding.'
  desc 'fix', 'Backup the ESX and management servers in accordance to the MAC level.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16201r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15852'
  tag rid: 'SV-16793r1_rule'
  tag stig_id: 'ESX0530'
  tag gtitle: 'The ESX Servers are not backed up.'
  tag fix_id: 'F-15806r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
