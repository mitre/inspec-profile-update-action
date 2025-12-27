control 'SV-227545' do
  title 'The /usr/aset/userlist file must not have an extended ACL.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', 'Check the permissions of the file.
# ls -lLd /usr/aset/userlist
If the permissions of the file or directory contains a "+", an extended ACL is present, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file. 
# chmod A- /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29707r488168_chk'
  tag severity: 'medium'
  tag gid: 'V-227545'
  tag rid: 'SV-227545r603266_rule'
  tag stig_id: 'GEN000000-SOL00270'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29695r488169_fix'
  tag 'documentable'
  tag legacy: ['SV-27015', 'V-22601']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
