control 'SV-29568' do
  title 'Removable media, remote file systems, and any file system not containing approved device files must be mounted with the nodev option.'
  desc 'The nodev (or equivalent) mount option causes the system to not handle device files as system devices. This option must be used for mounting any file system not containing approved device files. Device files can provide direct access to system hardware and can compromise security if not protected.'
  desc 'check', 'Each file system line entry must contain a device specific file and may additionally contain all of the following fields, in the following order:
mount directory, type, options, backup frequency, pass number (on parallel fsck) and comment.

Check /etc/fstab and verify that the nodevs mount option is used on all NFS file systems. If an NFS file system is not using the nodevs option, this is a finding.

# cat /etc/fstab | grep -v "^#" | grep nfs'
  desc 'fix', 'Edit /etc/fstab and add the nodevs mount option to all entries for NFS file systems.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36398r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22368'
  tag rid: 'SV-29568r1_rule'
  tag stig_id: 'GEN002430'
  tag gtitle: 'GEN002430'
  tag fix_id: 'F-31737r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
