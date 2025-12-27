control 'SV-52438' do
  title 'The /var/adm/userdb/USERDB.DISABLED file must be owned by root.'
  desc 'Unless the userdb is required, the /var/adm/userdb/USERDB.DISABLED file must be created to disable the use of per-user security attributes in the user database. Attributes in the user database override the system-wide settings configured in /etc/default/security. If the system-wide configuration is overridden maliciously, users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
If the userdb is required, this check is not applicable.

Verify the file is owned by root.
# ls -lL /var/adm/userdb/USERDB.DISABLED

If the file is not owned by root, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file ownership.
# chown root /var/adm/userdb/USERDB.DISABLED'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47011r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40451'
  tag rid: 'SV-52438r1_rule'
  tag stig_id: 'GEN000000-HPUX0280'
  tag gtitle: 'GEN000000-HPUX0280'
  tag fix_id: 'F-45400r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
