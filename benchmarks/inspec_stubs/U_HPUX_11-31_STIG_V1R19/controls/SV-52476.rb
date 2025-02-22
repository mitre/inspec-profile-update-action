control 'SV-52476' do
  title '/etc/pam_user.conf file must not have an extended ACL.'
  desc 'The /etc/pam_user.conf file is the per user configuration file for the Pluggable Authentication Module (PAM) architecture. It supports per user authentication, account, session, and password management. If the configuration is modified maliciously, users may gain unauthorized system access. The /etc/pam_user.conf file must not be configured unless it is required.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Verify the file has no extended ACL.
# ls -lL /etc/pam_user.conf

If the permissions include a “+”, the file has an extended ACL, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Remove the optional ACL from the file.
# chacl -z /etc/pam_user.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47027r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40487'
  tag rid: 'SV-52476r1_rule'
  tag stig_id: 'GEN000000-HPUX0440'
  tag gtitle: 'GEN000000-HPUX0440'
  tag fix_id: 'F-45436r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
