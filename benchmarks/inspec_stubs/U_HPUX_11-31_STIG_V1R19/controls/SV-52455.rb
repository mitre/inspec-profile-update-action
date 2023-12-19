control 'SV-52455' do
  title 'The /etc/security.dsc file must be group-owned by sys.'
  desc 'The /etc/security.dsc file is the system description file that contains all attributes and default values that are configurable on a per user basis in /var/adm/userdb. If the description file is modified maliciously, users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the file is group-owned by sys.
# ls -lL /etc/security.dsc

If the file is not group-owned by sys, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file group ownership.
# chgrp sys /etc/security.dsc'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47016r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40467'
  tag rid: 'SV-52455r1_rule'
  tag stig_id: 'GEN000000-HPUX0330'
  tag gtitle: 'GEN000000-HPUX0330'
  tag fix_id: 'F-45417r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
