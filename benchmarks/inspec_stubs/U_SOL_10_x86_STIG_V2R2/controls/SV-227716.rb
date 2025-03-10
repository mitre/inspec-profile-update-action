control 'SV-227716' do
  title 'System audit logs must be owned by root.'
  desc 'Failure to give ownership of system audit log files to root provides the designated owner and unauthorized users with the potential to access sensitive information.'
  desc 'check', 'Perform the following to determine the location of audit logs and then check the ownership.
# more /etc/security/audit_control
# ls -lLa <audit log dir>
If any audit log file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the audit log file(s).

Procedure:
# chown root <audit log file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29878r488732_chk'
  tag severity: 'medium'
  tag gid: 'V-227716'
  tag rid: 'SV-227716r603266_rule'
  tag stig_id: 'GEN002680'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-29866r488733_fix'
  tag 'documentable'
  tag legacy: ['V-812', 'SV-27271']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
