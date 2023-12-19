control 'SV-218472' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  Kernel core dumps may consume a considerable amount of disk space and may result in Denial of Service by exhausting the available space on the target file system.  The kernel core dump process may increase the amount of time a system is unavailable due to a crash.  Kernel core dumps can be useful for kernel debugging.'
  desc 'check', 'Verify the kdump service is not running.

Procedure:
# service kdump status
If "Kdump is operational" is returned, this is a finding.'
  desc 'fix', 'Disable kdump.
# service kdump stop
# chkconfig kdump off'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19947r562570_chk'
  tag severity: 'medium'
  tag gid: 'V-218472'
  tag rid: 'SV-218472r603259_rule'
  tag stig_id: 'GEN003510'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19945r562571_fix'
  tag 'documentable'
  tag legacy: ['V-22404', 'SV-64421']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
