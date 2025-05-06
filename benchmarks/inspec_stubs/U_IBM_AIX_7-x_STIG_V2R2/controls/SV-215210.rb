control 'SV-215210' do
  title 'AIX nosuid option must be enabled on all NFS client mounts.'
  desc 'Enabling the nosuid mount option prevents the system from granting owner or group-owner privileges to programs with the suid or sgid bit set. If the system does not restrict this access, users with unprivileged access to the local system may be able to acquire privileged access by executing suid or sgid files located on the mounted NFS file system.'
  desc 'check', 'Check the system for NFS mounts not using the "nosuid" option using command: 

# lsfs -v nfs 
Name            Nodename   Mount Pt               VFS   Size    Options    Auto Accounting
/home/doej        --         /mount/doej            nfs    786432    --              yes         no

If the "mounted" file systems do not have the "nosuid option", this is a finding.'
  desc 'fix', 'Edit "/etc/filesystems" and add the "nosuid" option for all NFS file systems. 

Remount the NFS file systems to make the change take effect.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16408r294081_chk'
  tag severity: 'medium'
  tag gid: 'V-215210'
  tag rid: 'SV-215210r508663_rule'
  tag stig_id: 'AIX7-00-001056'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16406r294082_fix'
  tag 'documentable'
  tag legacy: ['SV-101691', 'V-91593']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
