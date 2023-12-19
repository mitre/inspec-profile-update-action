control 'SV-26639' do
  title 'All local file systems must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash, thus preserving the integrity of data that may have otherwise been lost. Journaling file systems typically do not require consistency checks upon booting after a crash, which can improve system availability. Some file systems employ other mechanisms to ensure consistency which also satisfy this requirement.'
  desc 'check', 'Parse the /etc/fstab file for any mountable HFS file system entries:
# cat /etc/fstab | grep -v "^#" | grep -v "/stand" | grep hfs

If any /etc/fstab entries are displayed, this is a finding.'
  desc 'fix', 'Convert any local HFS filesystems to use journaling, ensuring file system consistency.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36520r1_chk'
  tag severity: 'low'
  tag gid: 'V-22422'
  tag rid: 'SV-26639r1_rule'
  tag stig_id: 'GEN003650'
  tag gtitle: 'GEN003650'
  tag fix_id: 'F-31880r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000553']
  tag nist: ['CP-10 (2)']
end
