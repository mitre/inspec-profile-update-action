control 'SV-832' do
  title 'The alias file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', 'Find the aliases file on the system.
Procedure:
# find / -name aliases -depth -print

Check the mode of the alias file.
Procedure:
# ls -lL <alias location>

If the alias file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/mail/aliases file (or equivalent, such as /usr/lib/aliases) to 0644.  

Procedure:
# chmod 0644 /etc/aliases'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8032r2_chk'
  tag severity: 'medium'
  tag gid: 'V-832'
  tag rid: 'SV-832r2_rule'
  tag stig_id: 'GEN004380'
  tag gtitle: 'GEN004380'
  tag fix_id: 'F-986r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
