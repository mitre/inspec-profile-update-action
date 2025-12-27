control 'SV-26994' do
  title 'The HP-UX /etc/securetty file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files. Unauthorized modification of the /etc/securetty file could cause Denial of Service to authorized system consoles or add unauthorized system consoles.'
  desc 'check', "Check the permissions of the file.
# ls -lLd /etc/securetty
If the permissions of the file or directory contains a '+', an extended ACL is present, and this is a finding."
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /etc/securetty'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-27937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22591'
  tag rid: 'SV-26994r1_rule'
  tag stig_id: 'GEN000000-HPUX0110'
  tag gtitle: 'GEN000000-HPUX0110'
  tag fix_id: 'F-24260r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
