control 'SV-38748' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'check', 'Procedure:
# grep -p bin: /etc/security/audit/config
Directories and files to search will be listed under the bin stanza.
#aclget <directory>/<file> 

Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the system audit file(s) and disable extended permissions.
 
#acledit <directory>/<file> and disable extended permissions'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37248r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22369'
  tag rid: 'SV-38748r1_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'GEN002710'
  tag fix_id: 'F-32466r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
