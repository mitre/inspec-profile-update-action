control 'SV-227808' do
  title 'The root file system must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash, thus, preserving the integrity of data that may have otherwise been lost.  Journaling file systems typically do not require consistent checks upon booting after a crash, which can improve system availability.  Some file systems employ other mechanisms to ensure consistency which also satisfy this requirement.'
  desc 'check', "Logging should be enabled for those types of files systems that do not turn on logging by default. 

Procedure:
# mount -v

UFS, JFS, VXFS, HFS, XFS, reiserfs, EXT3 and EXT4 all turn logging on by default and will not be a finding. The ZFS file system uses other mechanisms to provide for file system consistency, and will not be a finding. For other file systems types, if the root file system does not have the 'logging' option, this is a finding. If the 'nolog' option is set on the root file system, this is a finding."
  desc 'fix', 'Implement file system journaling for the root file system, or use a file system using other mechanisms to ensure consistency.  If the root file system supports journaling, enable it.  If the file system does not support journaling or another mechanism to ensure consistency, a migration to a different file system will be necessary.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36468r603007_chk'
  tag severity: 'medium'
  tag gid: 'V-227808'
  tag rid: 'SV-227808r603266_rule'
  tag stig_id: 'GEN003640'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36432r603008_fix'
  tag 'documentable'
  tag legacy: ['V-4304', 'SV-40021']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
