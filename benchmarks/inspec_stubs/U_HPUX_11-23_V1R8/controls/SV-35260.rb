control 'SV-35260' do
  title 'All NFS-exported system files and system directories must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group ownership of sensitive files or directories to root provides the members of the owning group with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', %q(The contents of the exports file will generally take the form of :
share <options>

List the exports.
# cat /etc/exports | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//' | cut -f 1,1 -d " "

Check the ownership of each exported directory.
# ls -lLd <exported directory>

If the directory is not group-owned by root, this is a finding.)
  desc 'fix', 'Change the group owner of the export directory.
# chgrp root <exported directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35096r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22496'
  tag rid: 'SV-35260r1_rule'
  tag stig_id: 'GEN005810'
  tag gtitle: 'GEN005810'
  tag fix_id: 'F-30365r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
