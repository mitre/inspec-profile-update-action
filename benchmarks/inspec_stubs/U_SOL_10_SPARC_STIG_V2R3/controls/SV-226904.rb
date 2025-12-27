control 'SV-226904' do
  title 'All local file systems must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash, thus preserving the integrity of data that may have otherwise been lost.  Journaling file systems typically do not require consistent checks upon booting after a crash, which can improve system availability.  Some file systems employ other mechanisms to ensure consistency which also satisfy this requirement.'
  desc 'check', "Verify local file systems use journaling or another mechanism ensuring file system consistency.

Procedure:
# mount -v | grep '^/dev/' | egrep -v '(logging|vxfs|zfs|devfs)' | grep -v /dev/fd

If a mount is listed, this is a finding."
  desc 'fix', 'Convert local file systems to use journaling or another mechanism ensuring file system consistency.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29066r484999_chk'
  tag severity: 'low'
  tag gid: 'V-226904'
  tag rid: 'SV-226904r603265_rule'
  tag stig_id: 'GEN003650'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29054r485000_fix'
  tag 'documentable'
  tag legacy: ['SV-26638', 'V-22422']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
