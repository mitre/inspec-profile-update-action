control 'SV-218473' do
  title 'The kernel core dump data directory must be owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Verify the location of the kernel core dump data directory:
# grep "path" /etc/kdump.conf

Note: If this setting is not configured or commented out, the default kernel dump data directory is /var/crash.

Check the ownership of the dump data directory:
# ls -ld <path to kernel core dump data directory>

If the kernel core dump data directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the kernel core dump data directory to root. 
# chown root <path to kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19948r562573_chk'
  tag severity: 'low'
  tag gid: 'V-218473'
  tag rid: 'SV-218473r603259_rule'
  tag stig_id: 'GEN003520'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19946r562574_fix'
  tag 'documentable'
  tag legacy: ['V-11997', 'SV-64427']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
