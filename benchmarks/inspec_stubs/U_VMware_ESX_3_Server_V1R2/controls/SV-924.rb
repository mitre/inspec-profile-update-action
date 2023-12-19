control 'SV-924' do
  title 'Device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'check', 'Find all device files existing anywhere on the system.

Procedure:
# find / -type b -print > devicelist
# find / -type c -print >> devicelist

Check the permissions on the directories above subdirectories containing device files.  If any of the device files or their parent directories is world-writable, excepting device files specifically intended to be world-writable, such as /dev/null, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the device file(s).

Procedure:
# chmod o-w <device file>

Document all changes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-465r2_chk'
  tag severity: 'medium'
  tag gid: 'V-924'
  tag rid: 'SV-924r2_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'GEN002280'
  tag fix_id: 'F-1078r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
