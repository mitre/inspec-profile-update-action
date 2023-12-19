control 'SV-52435' do
  title 'The /var/adm/userdb directory must be group-owned by sys.'
  desc 'The /var/adm/userdb directory is the system user database repository used for storing per-user security configuration information. If the configuration is modified maliciously, individual users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the directory is group-owned by sys.
# ls -lL /var/adm/userdb

If the directory is not group-owned by sys, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file group ownership.
# chgrp sys /var/adm/userdb'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47008r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40448'
  tag rid: 'SV-52435r1_rule'
  tag stig_id: 'GEN000000-HPUX0250'
  tag gtitle: 'GEN000000-HPUX0250'
  tag fix_id: 'F-45397r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
