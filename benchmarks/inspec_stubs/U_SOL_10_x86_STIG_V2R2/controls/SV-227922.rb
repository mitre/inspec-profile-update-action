control 'SV-227922' do
  title 'The nosuid option must be enabled on all NFS client mounts.'
  desc 'Enabling the nosuid mount option prevents the system from granting owner or group-owner privileges to programs with the setuid or setgid bit set.  If the system does not restrict this access, users with unprivileged access to the local system may be able to acquire privileged access by executing setuid or setgid files located on the mounted NFS file system.'
  desc 'check', 'Check the system for NFS mounts not using the nosuid option.

Procedure:
# mount -v | grep " type nfs " | grep -v nosetuid
OR
# grep nfs /etc/mnttab | grep -v nosuid | grep -v :vold

If the mounted file systems do not have the nosetuid/nosuid option, this is a finding.  NOTE:  Mount options for the volume management daemon (vold) are controlled by the /etc/rmmount.conf file.'
  desc 'fix', 'Edit /etc/vfstab and add the nosuid option for all NFS file systems. Remount the NFS file systems to make the change take effect.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30084r490180_chk'
  tag severity: 'medium'
  tag gid: 'V-227922'
  tag rid: 'SV-227922r603266_rule'
  tag stig_id: 'GEN005900'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30072r490181_fix'
  tag 'documentable'
  tag legacy: ['V-936', 'SV-28452']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
