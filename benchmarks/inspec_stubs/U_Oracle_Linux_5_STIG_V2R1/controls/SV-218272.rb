control 'SV-218272' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions to compromise the system.'
  desc 'check', "Verify all manual page files have no extended ACLs.
# ls -lLR /usr/share/man /usr/share/info /usr/share/infopage

If the permissions include a '+', the file has an extended ACL this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/share/man/* /usr/share/info/* /usr/share/infopage/*'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19747r561617_chk'
  tag severity: 'low'
  tag gid: 'V-218272'
  tag rid: 'SV-218272r603259_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19745r561618_fix'
  tag 'documentable'
  tag legacy: ['V-22316', 'SV-64521']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
