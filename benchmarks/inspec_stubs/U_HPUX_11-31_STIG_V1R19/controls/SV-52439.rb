control 'SV-52439' do
  title 'The /var/adm/userdb/USERDB.DISABLED file must be group-owned by sys.'
  desc 'Unless the userdb is required, the /var/adm/userdb/USERDB.DISABLED file must be created to disable the use of per-user security attributes in the user database. Attributes in the user database override the system-wide settings configured in /etc/default/security. If the system-wide configuration is overridden maliciously, users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
If the userdb is required, this check is not applicable.

Verify the file is group-owned by sys.
# ls -lL /var/adm/userdb/USERDB.DISABLED

If the file is not group-owned by sys, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file group ownership.
# chgrp sys /var/adm/userdb/USERDB.DISABLED'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47012r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40452'
  tag rid: 'SV-52439r1_rule'
  tag stig_id: 'GEN000000-HPUX0290'
  tag gtitle: 'GEN000000-HPUX0290'
  tag fix_id: 'F-45401r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
