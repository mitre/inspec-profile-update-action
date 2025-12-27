control 'SV-226901' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine the audit log data path.
# grep "^dir:" /etc/security/audit_control

Determine if the audit log data path is a separate filesystem.
# df -h <audit data path>  

If the returned mount point is "/" this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29063r484990_chk'
  tag severity: 'low'
  tag gid: 'V-226901'
  tag rid: 'SV-226901r603265_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29051r484991_fix'
  tag 'documentable'
  tag legacy: ['V-23738', 'SV-28628']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
