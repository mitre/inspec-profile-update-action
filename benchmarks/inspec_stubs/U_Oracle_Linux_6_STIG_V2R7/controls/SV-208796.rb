control 'SV-208796' do
  title 'The system must use a separate file system for user home directories.'
  desc 'Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.'
  desc 'check', 'Run the following command to determine if "/home" is on its own partition or logical volume: 

$ mount | grep "on /home "

If "/home" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.'
  desc 'fix', 'If user home directories will be stored locally, create a separate partition for "/home" at installation time (or migrate it later using LVM). If "/home" will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9049r357368_chk'
  tag severity: 'low'
  tag gid: 'V-208796'
  tag rid: 'SV-208796r793581_rule'
  tag stig_id: 'OL6-00-000007'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9049r357369_fix'
  tag 'documentable'
  tag legacy: ['V-50677', 'SV-64883']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
