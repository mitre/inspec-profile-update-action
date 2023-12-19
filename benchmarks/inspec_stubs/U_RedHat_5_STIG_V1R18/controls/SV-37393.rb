control 'SV-37393' do
  title 'All shells referenced in /etc/passwd must be listed in the /etc/shells file, except any shells specified for the purpose of preventing logins.'
  desc 'The shells file lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized unsecure shell.'
  desc 'check', 'Confirm the login shells referenced in the /etc/passwd file are listed in the /etc/shells file.

Procedure:
Determine which shells are permitted for use by users:
# more /etc/shells

Note: /usr/bin/false, /bin/false, /dev/null, /sbin/nologin, /bin/sync, /sbin/halt, /sbin/shutdown, (and equivalents) cannot be placed in the /etc/shells file.

Determine which shells are being used:
# more /etc/passwd (optionally shells found in /etc/passwd can be grepped for in /etc/shells)

If any shells are found that are not in /etc/shells, or if false shells are found in /etc/shells, then this is a finding.'
  desc 'fix', 'Use the "chsh" utility or edit the /etc/passwd file and correct the error by changing the default shell of the account in error to an acceptable shell name contained in the /etc/shells file.

Example:
# chsh -s /bin/bash testuser'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36080r3_chk'
  tag severity: 'medium'
  tag gid: 'V-917'
  tag rid: 'SV-37393r2_rule'
  tag stig_id: 'GEN002140'
  tag gtitle: 'GEN002140'
  tag fix_id: 'F-31324r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
