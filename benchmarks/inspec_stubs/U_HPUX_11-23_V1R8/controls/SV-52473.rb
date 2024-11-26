control 'SV-52473' do
  title 'The /etc/pam_user.conf file must be owned by root.'
  desc 'The /etc/pam_user.conf file is the per user configuration file for the Pluggable Authentication Module (PAM) architecture. It supports per user authentication, account, session, and password management. If the configuration is modified maliciously, users may gain unauthorized system access. The /etc/pam_user.conf file must not be configured unless it is required.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the file is owned by root.
# ls -lL /etc/pam_user.conf

If the file is not owned by root, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
As root, change the file ownership.
# chown root /etc/pam_user.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47024r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40484'
  tag rid: 'SV-52473r1_rule'
  tag stig_id: 'GEN000000-HPUX0410'
  tag gtitle: 'GEN000000-HPUX0410'
  tag fix_id: 'F-45433r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
