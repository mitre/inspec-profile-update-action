control 'SV-4352' do
  title 'The /etc/security/audit_user file must be owned by root.'
  desc 'The /etc/security/audit_user is a sensitive file and must be owned by root to prevent possible system compromise.'
  desc 'fix', 'Change the owner of the /etc/security/audit_user file to root.
# chown root /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4352'
  tag rid: 'SV-4352r2_rule'
  tag stig_id: 'GEN000000-SOL00060'
  tag gtitle: 'GEN000000-SOL00060'
  tag fix_id: 'F-4263r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
