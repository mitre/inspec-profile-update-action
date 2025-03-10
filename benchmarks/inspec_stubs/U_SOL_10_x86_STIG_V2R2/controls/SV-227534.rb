control 'SV-227534' do
  title 'The /etc/security/audit_user file must be owned by root.'
  desc 'The /etc/security/audit_user is a sensitive file and must be owned by root to prevent possible system compromise.'
  desc 'check', 'Check /etc/security/audit_user ownership.

# ls -lL /etc/security/audit_user

If /etc/security/audit_user is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/security/audit_user file to root.
# chown root /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29696r488129_chk'
  tag severity: 'medium'
  tag gid: 'V-227534'
  tag rid: 'SV-227534r603266_rule'
  tag stig_id: 'GEN000000-SOL00060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29684r488130_fix'
  tag 'documentable'
  tag legacy: ['SV-4352', 'V-4352']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
