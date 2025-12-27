control 'SV-226935' do
  title 'Files executed through a mail aliases file must not have extended ACLs.'
  desc 'Excessive permissions on files executed through a mail alias file could result in modification by an unauthorized user, execution of malicious code, and/or system compromise.'
  desc 'check', 'Examine the contents of the /etc/mail/aliases file.
For each file referenced, check the permissions of the file.
# ls -lL [file referenced from aliases]
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [file referenced from aliases]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29097r485114_chk'
  tag severity: 'medium'
  tag gid: 'V-226935'
  tag rid: 'SV-226935r603265_rule'
  tag stig_id: 'GEN004430'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29085r485115_fix'
  tag 'documentable'
  tag legacy: ['V-22441', 'SV-26696']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
