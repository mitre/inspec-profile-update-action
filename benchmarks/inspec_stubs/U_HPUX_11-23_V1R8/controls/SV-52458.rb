control 'SV-52458' do
  title 'The /etc/security.dsc file must not have an extended ACL.'
  desc 'The /etc/security.dsc file is the system description file that contains all attributes and default values that are configurable on a per user basis in /var/adm/userdb. If the description file is modified maliciously, users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the file has no extended ACL.
# ls -lL /etc/security.dsc

If the permissions include a “+”, the file has an extended ACL, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Remove the optional ACL from the file.
# chacl -z /etc/security.dsc'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47018r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40470'
  tag rid: 'SV-52458r1_rule'
  tag stig_id: 'GEN000000-HPUX0350'
  tag gtitle: 'GEN000000-HPUX0350'
  tag fix_id: 'F-45420r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
