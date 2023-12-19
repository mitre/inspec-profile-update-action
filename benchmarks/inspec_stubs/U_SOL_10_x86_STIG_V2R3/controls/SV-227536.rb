control 'SV-227536' do
  title 'The /etc/security/audit_user file must have mode 0640 or less permissive.'
  desc 'Audit_user is a sensitive file that, if compromised, would allow a malicious user to select auditing parameters to ignore his sessions.  This would allow malicious operations the auditing subsystem would not log for that user.'
  desc 'check', 'Check /etc/security/audit_user permissions.

# ls -lL /etc/security/audit_user

If /etc/security/audit_user is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the audit_user file to 0640.
# chmod 0640 /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29698r488135_chk'
  tag severity: 'medium'
  tag gid: 'V-227536'
  tag rid: 'SV-227536r603266_rule'
  tag stig_id: 'GEN000000-SOL00100'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-29686r488136_fix'
  tag 'documentable'
  tag legacy: ['V-4245', 'SV-4245']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
