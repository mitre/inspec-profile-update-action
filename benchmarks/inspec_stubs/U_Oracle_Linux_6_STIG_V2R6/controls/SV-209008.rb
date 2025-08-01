control 'SV-209008' do
  title 'Remote file systems must be mounted with the nodev option.'
  desc 'Legitimate device files should only exist in the /dev directory. NFS mounts should not present device files to users.'
  desc 'check', 'To verify the "nodev" option is configured for all NFS mounts, run the following command: 

$ mount | grep nfs

All NFS mounts should show the "nodev" setting in parentheses, along with other mount options. 
If the setting does not show, this is a finding.'
  desc 'fix', 'Add the "nodev" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9261r357809_chk'
  tag severity: 'medium'
  tag gid: 'V-209008'
  tag rid: 'SV-209008r793729_rule'
  tag stig_id: 'OL6-00-000269'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9261r357810_fix'
  tag 'documentable'
  tag legacy: ['V-50845', 'SV-65051']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
