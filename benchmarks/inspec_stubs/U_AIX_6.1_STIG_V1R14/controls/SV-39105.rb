control 'SV-39105' do
  title 'All local file systems must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash, thus preserving the integrity of data that may have otherwise been lost.  Journaling file systems typically do not require consistency checks upon booting after a crash, which can improve system availability.  Some file systems employ other mechanisms to ensure consistency which also satisfy this requirement.'
  desc 'check', 'Determine if the local file systems employ journaling or another mechanism ensuring file system consistency.

Procedure:
List all local file system mount points.
#/usr/sysv/bin/df -l | grep -v “/proc”
#lsfs < each file system returned>

If any file systems are not jfs or jfs2, this is a finding.'
  desc 'fix', 'Convert local file systems to use journaling or another mechanism ensuring file system consistency.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38098r3_chk'
  tag severity: 'low'
  tag gid: 'V-22422'
  tag rid: 'SV-39105r2_rule'
  tag stig_id: 'GEN003650'
  tag gtitle: 'GEN003650'
  tag fix_id: 'F-33371r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000553']
  tag nist: ['CP-10 (2)']
end
