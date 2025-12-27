control 'SV-831' do
  title 'The alias file must be owned by root.'
  desc 'If the alias file is not owned by root, an unauthorized user may modify the file to add aliases to run malicious code or redirect email.'
  desc 'check', 'Find the aliases file on the system.

Procedure:
# find / -name aliases -depth -print

Check the ownership of the alias file.

Procedure:
# ls -lL <alias location>

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/mail/aliases file (or equivalent, such as /usr/lib/aliases) to root.

Procedure:
# chown root /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-614r2_chk'
  tag severity: 'medium'
  tag gid: 'V-831'
  tag rid: 'SV-831r2_rule'
  tag stig_id: 'GEN004360'
  tag gtitle: 'GEN004360'
  tag fix_id: 'F-985r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
