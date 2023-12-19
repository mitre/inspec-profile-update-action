control 'SV-218475' do
  title 'The kernel core dump data directory must have mode 0700 or less permissive.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the mode of the kernel core dump data directory is more permissive than 0700, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', 'Verify the location of the kernel core dump data directory:
# grep "path" /etc/kdump.conf

Note: If this setting is not configured or commented out, the default kernel dump data directory is /var/crash.

Check the permissions of the dump data directory:
# ls -ld <path to kernel core dump data directory>

If the directory has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Set the permissions on the kernel core dump data directory to 0700.

# chmod 0700 <kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19950r562579_chk'
  tag severity: 'low'
  tag gid: 'V-218475'
  tag rid: 'SV-218475r603259_rule'
  tag stig_id: 'GEN003522'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19948r562580_fix'
  tag 'documentable'
  tag legacy: ['V-22406', 'SV-64433']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
