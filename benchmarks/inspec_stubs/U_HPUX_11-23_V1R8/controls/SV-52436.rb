control 'SV-52436' do
  title 'The /var/adm/userdb directory must have mode 0700 or less permissive.'
  desc 'The /var/adm/userdb directory is the system user database repository used for storing per-user security configuration information. If the configuration is modified maliciously, individual users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the directory mode.
# ls -lL /var/adm/userdb

If the directory mode is more permissive than 0700, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file mode to 0700 or less permissive.
# chmod 0700 /var/adm/userdb'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47009r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40449'
  tag rid: 'SV-52436r1_rule'
  tag stig_id: 'GEN000000-HPUX0260'
  tag gtitle: 'GEN000000-HPUX0260'
  tag fix_id: 'F-45398r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
