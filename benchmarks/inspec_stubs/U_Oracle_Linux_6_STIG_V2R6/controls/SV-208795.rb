control 'SV-208795' do
  title 'The system must use a separate file system for /var/log.'
  desc 'Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".'
  desc 'check', 'Run the following command to determine if "/var/log" is on its own partition or logical volume: 

$ mount | grep "on /var/log "

If "/var/log" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.'
  desc 'fix', 'System logs are stored in the "/var/log" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9048r357365_chk'
  tag severity: 'low'
  tag gid: 'V-208795'
  tag rid: 'SV-208795r793580_rule'
  tag stig_id: 'OL6-00-000003'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9048r357366_fix'
  tag 'documentable'
  tag legacy: ['SV-64735', 'V-50529']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
