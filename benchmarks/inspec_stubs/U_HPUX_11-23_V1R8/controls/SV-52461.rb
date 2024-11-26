control 'SV-52461' do
  title 'The /etc/pam.conf file must be owned by root.'
  desc '/etc/pam.conf file is the system configuration file for the Pluggable Authentication Module (PAM) architecture. It supports per user authentication, account, session, and password management. If the configuration is modified maliciously, users may gain unauthorized system access.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the file is owned by root.
# ls -lL /etc/pam.conf

If the file is not owned by root, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file ownership.
# chown root /etc/pam.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47019r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40473'
  tag rid: 'SV-52461r1_rule'
  tag stig_id: 'GEN000000-HPUX0360'
  tag gtitle: 'GEN000000-HPUX0360'
  tag fix_id: 'F-45423r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
