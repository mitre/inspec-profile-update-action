control 'SV-35191' do
  title 'All NFS-shared system files and system directories must be owned by root, or a system account.'
  desc "Failure to give ownership of sensitive files or directories  to root provides the designated owner and possible unauthorized users with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', "Check for NFS shared file systems.
# cat /etc/dfs/sharetab

This will display all of the shared file systems. For each file system displayed, check the ownership.

Check the owner  of the NFS share configuration file.
# echo ` ls -lLad <shared file system path>` | tr '\\011' ' ' | tr -s  ' ' | sed -e 's/^[  \\t]*//'  

If the files and directories are not owned by root or a system account, this is a finding."
  desc 'fix', 'Change the ownership of shared file systems not owned by root, or a system account.

# chown root <path>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-38000r2_chk'
  tag severity: 'medium'
  tag gid: 'V-931'
  tag rid: 'SV-35191r3_rule'
  tag stig_id: 'GEN005800'
  tag gtitle: 'GEN005800'
  tag fix_id: 'F-33234r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
