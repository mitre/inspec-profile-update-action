control 'SV-38957' do
  title 'The nosuid option must be enabled on all NFS client mounts.'
  desc 'Enabling the nosuid mount option prevents the system from granting owner or group-owner privileges to programs with the suid or sgid bit set.  If the system does not restrict this access, users with unprivileged access to the local system may be able to acquire privileged access by executing suid or sgid files located on the mounted NFS file system.'
  desc 'check', 'Check the system for NFS mounts not using the nosuid option. 
Procedure: 
# lsfs -v nfs
If the mounted file systems do not have the nosuid option, this is a finding.'
  desc 'fix', 'Edit /etc/filesystems and add the nosuid option for all NFS file systems. Remount the NFS file systems to make the change take effect.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38202r1_chk'
  tag severity: 'medium'
  tag gid: 'V-936'
  tag rid: 'SV-38957r1_rule'
  tag stig_id: 'GEN005900'
  tag gtitle: 'GEN005900'
  tag fix_id: 'F-32339r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator', 'Information Assurance Manager']
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
