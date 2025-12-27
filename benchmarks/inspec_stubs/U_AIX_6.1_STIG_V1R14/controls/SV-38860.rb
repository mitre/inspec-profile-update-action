control 'SV-38860' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in Denial of Service by exhausting the available space on the target file system. The kernel core dump process may increase the amount of time a system is unavailable due to a crash. Kernel core dumps can be useful for kernel debugging.'
  desc 'check', 'Determine if kernel core dumps are enabled on the system. 

#sysdumpdev -l

Look at both the primary and secondary dump devices.  If either the primary or secondary dump device is not /dev/sysdumpnull,  this is a finding.'
  desc 'fix', 'Disable kernel core dumps on the system by setting primary and secondary dump devices to sysdumpnull.   

#sysdumpdev -P -p /dev/sysdumpnull

#sysdumpdev -P -s /dev/sysdumpnull'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22404'
  tag rid: 'SV-38860r1_rule'
  tag stig_id: 'GEN003510'
  tag gtitle: 'GEN003510'
  tag fix_id: 'F-33115r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
