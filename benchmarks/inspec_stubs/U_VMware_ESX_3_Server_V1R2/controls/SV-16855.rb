control 'SV-16855' do
  title 'Virtual machines are not backed up in accordance with the MAC level.'
  desc 'Backups of the virtual machines are critical in order to recover from hardware problems, unexpected software errors, or a disaster to the computing facility. Data backup must be performed in accordance with its mission assurance category (MAC) level. For MAC III systems it is necessary to ensure that backups are performed weekly. For MAC II systems backups are performed daily and the recovery media is stored off-site in a protected facility in accordance with its mission assurance category and confidentiality level. In MAC I systems backups are maintained through a redundant secondary system which is not collocated, and can be activated without loss of data or disruption to the operation.'
  desc 'check', '1. Determine the MAC level of the virtual machines by asking the IAO/SA.
2. Once the MAC level is determined, locate the backup media or storage location.
    For MAC I servers, a redundant secondary system is required that is not colocated.
    For MAC II servers, daily backups are required with recovery media stored offline.
    For MAC III servers, backups must be performed weekly.
3. Depending on the MAC level, verify the virtual machines are backed up to media or storage within the guidelines of the MAC level.  If they are not, this is a finding.'
  desc 'fix', 'Backup all virtual machines according to the MAC level.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15913'
  tag rid: 'SV-16855r1_rule'
  tag stig_id: 'ESX1140'
  tag gtitle: 'Virtual machines are not backed up'
  tag fix_id: 'F-15871r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'CODB-1, CODB-2, CODB-3'
end
