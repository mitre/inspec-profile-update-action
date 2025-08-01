control 'SV-52441' do
  title 'The /var/adm/userdb/USERDB.DISABLED file must not have an extended ACL.'
  desc 'Unless the userdb is required, the /var/adm/userdb/USERDB.DISABLED file must be created to disable the use of per-user security attributes in the user database. Attributes in the user database override the system-wide settings configured in /etc/default/security. If the system-wide configuration is overridden maliciously, users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
If the userdb is required, this check is not applicable.

Verify the file has no extended ACL.
# ls -lL /var/adm/userdb/USERDB.DISABLED

If the permissions include a “+”, the file has an extended ACL, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Remove the optional ACL from the file.
# chacl -z /var/adm/userdb/USERDB.DISABLED'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47014r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40454'
  tag rid: 'SV-52441r1_rule'
  tag stig_id: 'GEN000000-HPUX0310'
  tag gtitle: 'GEN000000-HPUX0310'
  tag fix_id: 'F-45405r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
