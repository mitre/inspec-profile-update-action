control 'SV-218496' do
  title 'All local file systems must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash preserving the integrity of data that may have otherwise been lost.  Journaling file systems typically do not require consistency checks upon booting after a crash, which can improve system availability.  Some file systems employ other mechanisms to ensure consistency also satisfying this requirement.'
  desc 'check', "Verify local filesystems use journaling.
# mount | grep '^/dev/' | egrep -v 'type (ext3|ext4|jfs|reiserfs|xfs|iso9660|udf)'
If a mount is listed, this is a finding."
  desc 'fix', 'Convert local file systems to use journaling or another mechanism ensuring file system consistency.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19971r562624_chk'
  tag severity: 'low'
  tag gid: 'V-218496'
  tag rid: 'SV-218496r603259_rule'
  tag stig_id: 'GEN003650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19969r562625_fix'
  tag 'documentable'
  tag legacy: ['V-22422', 'SV-64227']
  tag cci: ['CCI-000366', 'CCI-000553']
  tag nist: ['CM-6 b', 'CP-10 (2)']
end
