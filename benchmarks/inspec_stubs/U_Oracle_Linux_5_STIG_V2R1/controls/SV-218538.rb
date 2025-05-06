control 'SV-218538' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20013r562735_chk'
  tag severity: 'medium'
  tag gid: 'V-218538'
  tag rid: 'SV-218538r603259_rule'
  tag stig_id: 'GEN004430'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20011r562736_fix'
  tag 'documentable'
  tag legacy: ['V-22441', 'SV-63745']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
