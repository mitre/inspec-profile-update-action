control 'SV-38810' do
  title 'Files executed through a mail aliases file must not have extended ACLs.'
  desc 'Excessive permissions on files executed through a mail alias file could result in modification by an unauthorized user, execution of malicious code, and/or system compromise.'
  desc 'check', 'Examine the contents of the /etc/mail/aliases file.
For each file referenced, check the permissions of the file.

#aclget [File referenced from alias] 

Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file(s) referenced from the aliases file and disable extended permissions.

#acledit [File referenced from aliases]'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22441'
  tag rid: 'SV-38810r1_rule'
  tag stig_id: 'GEN004430'
  tag gtitle: 'GEN004430'
  tag fix_id: 'F-31912r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
