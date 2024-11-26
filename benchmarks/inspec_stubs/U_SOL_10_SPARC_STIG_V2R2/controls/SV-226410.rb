control 'SV-226410' do
  title 'The /etc/security/audit_user file must not have an extended ACL.'
  desc 'Audit_user is a sensitive file that, if compromised, would allow a malicious user to select auditing parameters to ignore their sessions.  This would allow malicious operations the auditing subsystem would not detect for that user.  It could also result in long-term system compromise possibly leading to the compromise of other systems and networks.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/security/audit_user
If the permissions of the file contain a "+", an extended ACL is present, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/security/audit_user'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28571r482585_chk'
  tag severity: 'medium'
  tag gid: 'V-226410'
  tag rid: 'SV-226410r603265_rule'
  tag stig_id: 'GEN000000-SOL00110'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28559r482586_fix'
  tag 'documentable'
  tag legacy: ['SV-27004', 'V-22599']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
