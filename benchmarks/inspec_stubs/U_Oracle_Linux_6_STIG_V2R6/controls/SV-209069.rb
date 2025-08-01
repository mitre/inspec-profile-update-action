control 'SV-209069' do
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc 'All filesystems that are required for the successful operation of the system should be explicitly listed in "/etc/fstab" by an administrator. New filesystems should not be arbitrarily introduced via the automounter.

The "autofs" daemon mounts and unmounts filesystems, such as user home directories shared via NFS, on demand. In addition, autofs can be used to handle removable media, and the default configuration provides the cdrom device as "/misc/cd". However, this method of providing access to removable media is not common, so autofs can almost always be disabled if NFS is not in use. Even if NFS is required, it is almost always possible to configure filesystem mounts statically by editing "/etc/fstab" rather than relying on the automounter.'
  desc 'check', 'To verify the "autofs" service is disabled, run the following command: 

chkconfig --list autofs

If properly configured, the output should be the following: 

autofs 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Verify the "autofs" service is not running:

# service autofs status

If the autofs service is enabled or running, this is a finding.'
  desc 'fix', 'If the "autofs" service is not needed to dynamically mount NFS filesystems or removable media, disable the service for all runlevels: 

# chkconfig --level 0123456 autofs off

Stop the service if it is already running: 

# service autofs stop'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9322r357992_chk'
  tag severity: 'low'
  tag gid: 'V-209069'
  tag rid: 'SV-209069r793790_rule'
  tag stig_id: 'OL6-00-000526'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9322r357993_fix'
  tag 'documentable'
  tag legacy: ['V-50515', 'SV-64721']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
