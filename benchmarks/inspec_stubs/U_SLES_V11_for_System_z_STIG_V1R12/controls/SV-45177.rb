control 'SV-45177' do
  title 'Device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'check', 'Find all world-writable device files existing anywhere on the system.

Procedure:
# find / -perm -2 -a \\( -type b -o -type c \\) > devicelist
Check the permissions on the directories above subdirectories containing device files. If any of the device files or their parent directories are world-writable, excepting device files specifically intended to be world-writable such as /dev/null, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the device file(s).

Procedure:
# chmod o-w <device file>

Document all changes.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42522r1_chk'
  tag severity: 'medium'
  tag gid: 'V-924'
  tag rid: 'SV-45177r1_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'GEN002280'
  tag fix_id: 'F-38575r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
