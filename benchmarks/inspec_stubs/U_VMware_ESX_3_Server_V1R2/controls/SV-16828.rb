control 'SV-16828' do
  title 'Master templates are not stored on a separate partition.'
  desc 'The master templates will be stored in a separate partition (NTFS, VMFS, etc) from the production virtual machines. Partitioning the master templates isolates them from system, application, and user files. This isolation helps protect the disk space used by the operating system and various applications. Files cannot grow across partitions. Another advantage is that if a bad spot develops on the hard drive, the risk to the data is reduced as is recovery time. Furthermore, separate master template partitions provide the ability to set up certain directories as read-only file systems.'
  desc 'check', 'Perform the following on the ESX Server service console to determine if the /Master, /Utilities, /vmimages, or /(the name of the partition) are on separate disk partitions:

# vdf -h

Examine the Mounted on column for the disk device and ensure the device label for /Master, /Utilities, or /vmimages is not the same as the root filesystem.  If they are the same, this is a finding.'
  desc 'fix', 'Store all master templates on a separate partition.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16246r1_chk'
  tag severity: 'low'
  tag gid: 'V-15887'
  tag rid: 'SV-16828r1_rule'
  tag stig_id: 'ESX0910'
  tag gtitle: 'Master templates are not stored correctly'
  tag fix_id: 'F-15847r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Machine Administrator]', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
