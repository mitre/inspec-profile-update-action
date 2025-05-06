control 'SV-227622' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions that may compromise the system.'
  desc 'check', 'Verify all manual page files have no extended ACLs. Check environment variable $MANPATH for full list of manpage locations. 
# echo $MANPATH 
Check for ACLs, note only a partial list is presented below. 
# ls -lLR /usr/share/man /usr/sfw/man /usr/sfw/share/man

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [file with extended ACL]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29784r488423_chk'
  tag severity: 'low'
  tag gid: 'V-227622'
  tag rid: 'SV-227622r603266_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29772r488424_fix'
  tag 'documentable'
  tag legacy: ['V-22316', 'SV-26373']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
