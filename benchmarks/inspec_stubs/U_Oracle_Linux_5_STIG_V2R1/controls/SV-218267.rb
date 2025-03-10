control 'SV-218267' do
  title 'All system files, programs, and directories must be owned by a system account.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the ownership of system files, programs, and directories.

Procedure:
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/usb /sbin /usr/sbin

If any of the system files, programs, or directories are not owned by a system account, this is a finding.'
  desc 'fix', 'Change the owner of system files, programs, and directories to a system account.

Procedure:
# chown root /some/system/file

(A different system user may be used in place of root.)'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19742r554138_chk'
  tag severity: 'medium'
  tag gid: 'V-218267'
  tag rid: 'SV-218267r603259_rule'
  tag stig_id: 'GEN001220'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19740r554139_fix'
  tag 'documentable'
  tag legacy: ['V-795', 'SV-64483']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
