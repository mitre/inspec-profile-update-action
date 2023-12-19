control 'SV-4245' do
  title 'The /etc/security/audit_user file must have mode 0640 or less permissive.'
  desc 'Audit_user is a sensitive file that, if compromised, would allow a malicious user to select auditing parameters to ignore his sessions.  This would allow malicious operations the auditing subsystem would not log for that user.'
  desc 'fix', 'Change the mode of the audit_user file to 0640.
# chmod 0640 /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4245'
  tag rid: 'SV-4245r2_rule'
  tag stig_id: 'GEN000000-SOL00100'
  tag gtitle: 'GEN000000-SOL00100'
  tag fix_id: 'F-4156r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
