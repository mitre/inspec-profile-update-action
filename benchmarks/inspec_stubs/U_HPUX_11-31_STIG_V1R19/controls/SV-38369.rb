control 'SV-38369' do
  title 'Files executed through a mail aliases file must not have extended ACLs.'
  desc 'Excessive permissions on files executed through a mail alias file could result in modification by an unauthorized user, execution of malicious code, and/or system compromise.'
  desc 'check', 'Examine the contents of the /etc/mail/aliases file.
For each file referenced, check the permissions of the file.
# ls -lL <file referenced from aliases>
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36563r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22441'
  tag rid: 'SV-38369r1_rule'
  tag stig_id: 'GEN004430'
  tag gtitle: 'GEN004430'
  tag fix_id: 'F-31931r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
