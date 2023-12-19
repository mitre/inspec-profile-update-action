control 'SV-219541' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'Placing "/var/log/audit" in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space.'
  desc 'check', 'Run the following command to determine if "/var/log/audit" is on its own partition or logical volume: 

$ mount | grep "on /var/log/audit "

If "/var/log/audit" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.'
  desc 'fix', 'Audit logs are stored in the "/var/log/audit" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to store all audit logs that will be created by the auditing daemon.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21266r358163_chk'
  tag severity: 'low'
  tag gid: 'V-219541'
  tag rid: 'SV-219541r603263_rule'
  tag stig_id: 'OL6-00-000004'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21265r358164_fix'
  tag 'documentable'
  tag legacy: ['SV-64867', 'V-50661']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
