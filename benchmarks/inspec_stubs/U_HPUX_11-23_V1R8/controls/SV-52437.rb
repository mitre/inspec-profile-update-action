control 'SV-52437' do
  title 'The /var/adm/userdb directory must not have an extended ACL.'
  desc 'The /var/adm/userdb directory is the system user database repository used for storing per-user security configuration information. If the configuration is modified maliciously, individual users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the directory has no extended ACL.
# ls -lL /var/adm/userdb

If the permissions include a “+”, the directory has an extended ACL, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Remove the optional ACL from the file.
# chacl -z /var/adm/userdb'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47010r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40450'
  tag rid: 'SV-52437r1_rule'
  tag stig_id: 'GEN000000-HPUX0270'
  tag gtitle: 'GEN000000-HPUX0270'
  tag fix_id: 'F-45399r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
