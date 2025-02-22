control 'SV-215184' do
  title 'AIX device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'check', 'Find all device files existing anywhere on the system using commands:
# find / -type b -print | xargs ls -l > devicelistB
# find / -type c -print | xargs ls -l > devicelistC 

Look at devicelistB and devicelistC files to check the permissions on the device files and directories above the subdirectories containing device files.

If any of the device files or their parent directories are world-writable, excepting device files specifically intended to be world-writable, such as "/dev/null", this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the device file(s) using command:
# chmod o-w <device file>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16382r294003_chk'
  tag severity: 'medium'
  tag gid: 'V-215184'
  tag rid: 'SV-215184r508663_rule'
  tag stig_id: 'AIX7-00-001019'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-16380r294004_fix'
  tag 'documentable'
  tag legacy: ['SV-101581', 'V-91483']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
