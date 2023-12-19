control 'SV-218533' do
  title 'The alias file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect e-mail.'
  desc 'check', 'If the "sendmail" and "postfix" packages are not installed, this is not applicable.

Check the permissions of the alias file.

Procedure:
for sendmail:

# ls -lL /etc/aliases /etc/aliases.db

If an alias file has a mode more permissive than 0644, this is a finding.

for postfix:
Verify the location of the alias file.

# postconf alias_maps

This will return the location of the "aliases" file, by default "/etc/postfix/aliases".

# ls -lL <postfix aliases file> <postfix aliases.db file>

If an alias file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the alias files as needed to function.

No higher than 0644.

Procedure:
for sendmail:

# chmod 0644 /etc/aliases /etc/aliases.db

for postfix (assuming the default postfix directory):
# chmod 0644 /etc/postfix/aliases /etc/postfix/aliases'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20008r562720_chk'
  tag severity: 'medium'
  tag gid: 'V-218533'
  tag rid: 'SV-218533r603259_rule'
  tag stig_id: 'GEN004380'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20006r562721_fix'
  tag 'documentable'
  tag legacy: ['V-832', 'SV-63637']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
