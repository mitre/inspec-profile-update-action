control 'SV-215397' do
  title 'AIX kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in Denial of Service by exhausting the available space on the target file system. The kernel core dump process may increase the amount of time a system is unavailable due to a crash. Kernel core dumps can be useful for kernel debugging.'
  desc 'check', 'Determine if kernel core dumps are enabled on the system using command: 

# sysdumpdev -l 
primary              /dev/sysdumpnull
secondary            /dev/sysdumpnull

Look at both the primary and secondary dump devices. 

If either the primary or secondary dump device is not "/dev/sysdumpnull", this is a finding.'
  desc 'fix', 'Disable kernel core dumps on the system by setting primary and secondary dump devices to "sysdumpnull" by running following commands:
# sysdumpdev -P -p /dev/sysdumpnull 
# sysdumpdev -P -s /dev/sysdumpnull'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16595r294642_chk'
  tag severity: 'medium'
  tag gid: 'V-215397'
  tag rid: 'SV-215397r508663_rule'
  tag stig_id: 'AIX7-00-003094'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16593r294643_fix'
  tag 'documentable'
  tag legacy: ['SV-101801', 'V-91703']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
