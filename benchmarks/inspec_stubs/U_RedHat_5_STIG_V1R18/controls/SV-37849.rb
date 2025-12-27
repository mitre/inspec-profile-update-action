control 'SV-37849' do
  title 'All Network File System (NFS) exported system files and system directories must be owned by root.'
  desc "Failure to give ownership of sensitive files or directories  to root provides the designated owner and possible unauthorized users with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', 'Check for NFS exported file systems.

Procedure:
# cat /etc/exports
For each file system displayed, check the ownership.

# ls -lLa <exported file system path>

If the files and directories are not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of exported file systems not owned by root.

Procedure:
# chown root <path>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37045r1_chk'
  tag severity: 'medium'
  tag gid: 'V-931'
  tag rid: 'SV-37849r1_rule'
  tag stig_id: 'GEN005800'
  tag gtitle: 'GEN005800'
  tag fix_id: 'F-32313r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
