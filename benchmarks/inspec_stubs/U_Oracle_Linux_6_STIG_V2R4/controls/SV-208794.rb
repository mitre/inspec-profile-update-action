control 'SV-208794' do
  title 'The system must use a separate file system for /var.'
  desc 'Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the "/var" directory to contain world-writable directories, installed by other software packages.'
  desc 'check', 'Run the following command to determine if "/var" is on its own partition or logical volume: 

$ mount | grep "on /var "

If "/var" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.'
  desc 'fix', 'The "/var" directory is used by daemons and other system services to store frequently-changing data. Ensure that "/var" has its own partition or logical volume at installation time, or migrate it using LVM.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9047r357362_chk'
  tag severity: 'low'
  tag gid: 'V-208794'
  tag rid: 'SV-208794r603263_rule'
  tag stig_id: 'OL6-00-000002'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9047r357363_fix'
  tag 'documentable'
  tag legacy: ['SV-64743', 'V-50537']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
