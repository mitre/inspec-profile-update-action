control 'SV-931' do
  title 'All NFS-exported system files and system directories must be owned by root.'
  desc "Failure to give ownership of sensitive files or directories  to root provides the designated owner and possible unauthorized users with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', 'Check for NFS exported file systems.

Procedure:
# exportfs -v

This will display all of the exported file systems.  For each file system displayed, check the ownership.

Procedure:
# ls -lLa <exported file system path>

If the files and directories are not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of exported file systems not owned by root.

Procedure:
# chown root <path>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-862r2_chk'
  tag severity: 'medium'
  tag gid: 'V-931'
  tag rid: 'SV-931r2_rule'
  tag stig_id: 'GEN005800'
  tag gtitle: 'GEN005800'
  tag fix_id: 'F-1085r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
