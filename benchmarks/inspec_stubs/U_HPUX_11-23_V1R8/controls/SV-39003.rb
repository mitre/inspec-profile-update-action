control 'SV-39003' do
  title 'All NFS-exported system files and system directories must be owned by root.'
  desc "Failure to give ownership of sensitive files or directories  to root provides the designated owner and possible unauthorized users with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', "Check for NFS exported file systems.
# cat /etc/exports

This will display all of the exported file systems. For each file system displayed, check the ownership.

Check the owner  of the NFS export configuration file.
# echo ` ls -lLad <export file system path>` | tr '\\011' ' ' | tr -s  ' ' | sed -e 's/^[  \\t]*//'  

If the files and directories are not owned by root, this is a finding."
  desc 'fix', 'Change the ownership of exported file systems not owned by root.
# chown root <path>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35036r1_chk'
  tag severity: 'medium'
  tag gid: 'V-931'
  tag rid: 'SV-39003r1_rule'
  tag stig_id: 'GEN005800'
  tag gtitle: 'GEN005800'
  tag fix_id: 'F-30327r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
