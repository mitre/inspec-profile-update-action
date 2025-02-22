control 'SV-221753' do
  title 'The Oracle Linux operating system must disable Kernel core dumps unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space, and may result in denial of service by exhausting the available space on the target file system partition.'
  desc 'check', 'Verify that kernel core dumps are disabled unless needed.

Check the status of the "kdump" service with the following command:

# systemctl status kdump.service
kdump.service - Crash recovery kernel arming
Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)
Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago
Main PID: 1130 (code=exited, status=0/SUCCESS)
kernel arming.

If the "kdump" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).

If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If kernel core dumps are not required, disable the "kdump" service with the following command:

# systemctl disable kdump.service

If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23468r419331_chk'
  tag severity: 'medium'
  tag gid: 'V-221753'
  tag rid: 'SV-221753r603260_rule'
  tag stig_id: 'OL07-00-021300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23457r419332_fix'
  tag 'documentable'
  tag legacy: ['SV-108349', 'V-99245']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
