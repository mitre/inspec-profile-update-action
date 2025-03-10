control 'SV-218634' do
  title 'The nosuid option must be enabled on all Network File System (NFS) client mounts.'
  desc 'Enabling the nosuid mount option prevents the system from granting owner or group-owner privileges to programs with the suid or sgid bit set.  If the system does not restrict this access, users with unprivileged access to the local system may be able to acquire privileged access by executing suid or sgid files located on the mounted NFS file system.'
  desc 'check', 'Check the system for NFS mounts not using the "nosuid" option.

Procedure:
# mount -v | grep " type nfs " | egrep -v "nosuid"

If the mounted file systems do not have the "nosuid" option, this is a finding.'
  desc 'fix', 'Edit "/etc/fstab" and add the "nosuid" option for all NFS file systems. Remount the NFS file systems to make the change take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20109r562879_chk'
  tag severity: 'medium'
  tag gid: 'V-218634'
  tag rid: 'SV-218634r603259_rule'
  tag stig_id: 'GEN005900'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20107r562880_fix'
  tag 'documentable'
  tag legacy: ['V-936', 'SV-64147']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
