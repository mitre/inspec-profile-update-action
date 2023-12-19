control 'SV-796' do
  title 'System files, programs, and directories must be group-owned by a system group.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'fix', 'Change the group owner of system files to a system group.

Procedure:
# chgrp root /path/to/system/file

(System groups other than root may be used.)'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-796'
  tag rid: 'SV-796r2_rule'
  tag stig_id: 'GEN001240'
  tag gtitle: 'GEN001240'
  tag fix_id: 'F-950r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
