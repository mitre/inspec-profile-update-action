control 'SV-208793' do
  title 'The system must use a separate file system for /tmp.'
  desc 'The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it.'
  desc 'check', 'Run the following command to determine if "/tmp" is on its own partition or logical volume: 

$ mount | grep "on /tmp "

If "/tmp" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.'
  desc 'fix', 'The "/tmp" directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9046r357359_chk'
  tag severity: 'low'
  tag gid: 'V-208793'
  tag rid: 'SV-208793r793578_rule'
  tag stig_id: 'OL6-00-000001'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9046r357360_fix'
  tag 'documentable'
  tag legacy: ['SV-64739', 'V-50533']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
