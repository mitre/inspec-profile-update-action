control 'SV-35204' do
  title 'The nosuid option must be enabled on all NFS client mounts.'
  desc 'Enabling the nosuid mount option prevents the system from granting owner or group-owner privileges to programs with the suid or sgid bit set.  If the system does not restrict this access, users with unprivileged access to the local system may be able to acquire privileged access by executing suid or sgid files located on the mounted NFS file system.'
  desc 'check', 'Check the system for NFS mounts that do not use the nosuid option.
# mount -v | grep " type nfs " | grep -v "nosuid"

If the mounted file systems do not have the nosuid option, this is a finding.'
  desc 'fix', 'Edit /etc/fstab and add the nosuid option for all NFS file systems. Remount the NFS file systems to make the change take effect.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35048r1_chk'
  tag severity: 'medium'
  tag gid: 'V-936'
  tag rid: 'SV-35204r1_rule'
  tag stig_id: 'GEN005900'
  tag gtitle: 'GEN005900'
  tag fix_id: 'F-30338r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Manager', 'Information Assurance Officer']
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
