control 'SV-38467' do
  title 'System files, programs, and directories must be group-owned by a system group.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the group ownership of system files, programs, and directories.

Procedure:
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/usb /sbin /usr/sbin

If any system file, program, or directory is not owned by a system group, this is a finding.'
  desc 'fix', 'Change the group owner of system files to a system group.

Procedure:
# chgrp root <path>/<system file>

(System groups other than root may be used.)'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36310r1_chk'
  tag severity: 'medium'
  tag gid: 'V-796'
  tag rid: 'SV-38467r1_rule'
  tag stig_id: 'GEN001240'
  tag gtitle: 'GEN001240'
  tag fix_id: 'F-31565r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
