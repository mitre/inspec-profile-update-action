control 'SV-217848' do
  title 'The system must use a separate file system for /var/log.'
  desc 'Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".'
  desc 'check', 'Run the following command to determine if "/var/log" is on its own partition or logical volume: 

$ mount | grep "on /var/log "

If "/var/log" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.'
  desc 'fix', 'System logs are stored in the "/var/log" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19329r376559_chk'
  tag severity: 'low'
  tag gid: 'V-217848'
  tag rid: 'SV-217848r603264_rule'
  tag stig_id: 'RHEL-06-000003'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19327r376560_fix'
  tag 'documentable'
  tag legacy: ['V-38463', 'SV-50263']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
