control 'SV-37553' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36204r3_chk'
  tag severity: 'medium'
  tag gid: 'V-924'
  tag rid: 'SV-37553r3_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'GEN002280'
  tag fix_id: 'F-31464r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
