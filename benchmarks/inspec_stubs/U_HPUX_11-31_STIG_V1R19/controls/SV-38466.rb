control 'SV-38466' do
  title 'All system files, programs, and directories must be owned by a system account.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the ownership of system files, programs, and directories.

Procedure:
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/usb /sbin /usr/sbin

If any of the system files, programs, or directories are not owned by a system account, this is a finding.'
  desc 'fix', 'Change the owner of system files, programs, and directories to a system account.

Procedure:
# chown root <path>/<system file>

(A different system user may be used in place of root.)'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-795'
  tag rid: 'SV-38466r1_rule'
  tag stig_id: 'GEN001220'
  tag gtitle: 'GEN001220'
  tag fix_id: 'F-31564r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
