control 'SV-45854' do
  title 'Files executed through a mail aliases file must not have extended ACLs.'
  desc 'Excessive permissions on files executed through a mail aliases file could result in modification by an unauthorized user, execution of malicious code, and/or system compromise.'
  desc 'check', "Examine the contents of the /etc/aliases file.

Procedure:
# more /etc/aliases
Examine the aliases file for any utilized directories or paths.

# ls -lL <file referenced from aliases>
Check the permissions for any paths referenced. 
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43152r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22441'
  tag rid: 'SV-45854r1_rule'
  tag stig_id: 'GEN004430'
  tag gtitle: 'GEN004430'
  tag fix_id: 'F-39238r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
