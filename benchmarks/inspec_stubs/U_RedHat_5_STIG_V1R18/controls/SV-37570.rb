control 'SV-37570' do
  title 'The kernel core dump data directory must be owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Verify the location of the kernel core dump data directory:
# grep “path” /etc/kdump.conf

Note: If this setting is not configured or commented out, the default kernel dump data directory is /var/crash.

Check the ownership of the dump data directory:
# ls –ld <path to kernel core dump data directory>

If the kernel core dump data directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the kernel core dump data directory to root. 
# chown root <path to kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36351r2_chk'
  tag severity: 'low'
  tag gid: 'V-11997'
  tag rid: 'SV-37570r2_rule'
  tag stig_id: 'GEN003520'
  tag gtitle: 'GEN003520'
  tag fix_id: 'F-31608r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
