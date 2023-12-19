control 'SV-248628' do
  title 'OL 8 must disable kernel dumps unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.

OL 8 installation media presents the option to enable or disable the kdump service at the time of system installation.'
  desc 'check', 'Verify that kernel core dumps are disabled unless needed with the following command:

$ sudo systemctl status kdump.service

kdump.service - Crash recovery kernel arming
Loaded: loaded (/usr/lib/systemd/system/kdump.service; disabled; vendor preset: enabled)
Active: failed (Result: exit-code)since Mon 2020-05-04 16:08:09 EDT; 3min ago
Main PID: 1130 (code=exited, status=0/FAILURE)

If the "kdump" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).

If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If kernel core dumps are not required, disable the "kdump" service with the following command:

$ sudo systemctl disable kdump.service

If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52062r779448_chk'
  tag severity: 'medium'
  tag gid: 'V-248628'
  tag rid: 'SV-248628r779450_rule'
  tag stig_id: 'OL08-00-010670'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-52016r779449_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
