control 'SV-227643' do
  title 'The /etc/passwd file must not have an extended ACL.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.  The /etc/passwd file contains the list of local system accounts. It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Verify /etc/passwd has no extended ACL.
# ls -l /etc/passwd
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/passwd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29805r488489_chk'
  tag severity: 'medium'
  tag gid: 'V-227643'
  tag rid: 'SV-227643r603266_rule'
  tag stig_id: 'GEN001390'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29793r488490_fix'
  tag 'documentable'
  tag legacy: ['V-22334', 'SV-26429']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
