control 'SV-16795' do
  title 'Backups are not located in separate logical partitions from production data.'
  desc 'Since backups are critical to the recovery of the virtualization infrastructure, storing these files on the same logical location as the production servers is not recommended.  The backup files will be stored on a separate logical partition so restoration is possible in case of any hardware failures on the production physical servers.'
  desc 'check', 'Ask the IAO/SA to show you the location of the backup data for the ESX Servers, VirtualCenter servers, virtual machines, and any other virtual infrastructure applications. If the backup data is on separate physical media, this would not be a finding.  If the backups are located on a SAN, verify that the production data is logically partitioned from the backup media.  If the backup data is on the same partition as the production data, this is a finding.'
  desc 'fix', 'Place backup data on a separate partition from the production data.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15854'
  tag rid: 'SV-16795r1_rule'
  tag stig_id: 'ESX0550'
  tag gtitle: 'Backups are not on separate logical partitions.'
  tag fix_id: 'F-15808r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
