control 'SV-218358' do
  title 'Device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'check', 'Find all world-writable device files existing anywhere on the system.

Procedure:
# find / -perm -2 -a \\( -type b -o -type c \\) > devicelist

Check the permissions on the directories above subdirectories containing device files.

If any of the device files or their parent directories are world-writable, excepting device files specifically intended to be world-writable such as /dev/null, this is a finding.

These world-writable files on installation are intended to be world-writable:

/dev/full
/dev/null
/selinux/null
/dev/ptmx
/dev/random
/dev/tty
/dev/vsock
/dev/zero
/dev/log'
  desc 'fix', 'Remove the world-writable permission from the device file(s).

Procedure:

# chmod o-w <device file>

Document all changes.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19833r569038_chk'
  tag severity: 'medium'
  tag gid: 'V-218358'
  tag rid: 'SV-218358r603259_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19831r569039_fix'
  tag 'documentable'
  tag legacy: ['V-924', 'SV-63229']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
