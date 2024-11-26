control 'SV-35054' do
  title 'The system must use a separate file system for the system audit data path..'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'fix', 'Migrate the audit log path onto a separate filesystem. The following assumes that /var exists and that the new audit log mount point will be
/var/.audit.

Verify if auditing is running:
# ps -ef | grep audomon | grep -v grep

If auditing is running, issue the stop command:
# /sbin/init.d/auditing stop

Use SAM/SMH to:
	- Create a new Logical Volume (size to be determined based on local site requirements).
	- Create a VxFS file system on the new logical  volume, paying special attention to site requirements such as Access Permissions, Allocation Policies, Mirroring considerations, large/no-large files and mount options such 
as suid/nosuid and ro/rw.

Verify the /etc/fstab /var/.audit entry
# more /etc/fstab

Verify the current mounts:
# mount

Mount /var/.audit if not yet mounted:
# mount -a

Re-start the auditing subsystem:
# /sbin/init.d/auditing start

Verify that auditing is now running:
# ps -ef | grep audomon | grep -v grep'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-23738'
  tag rid: 'SV-35054r1_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'GEN003623'
  tag fix_id: 'F-30229r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
