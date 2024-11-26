control 'SV-239529' do
  title 'The alias files must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the alias files may permit unauthorized modification. If an alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', 'Check the permissions of the alias files:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If the alias files have a mode more permissive than "0644", this is a finding.'
  desc 'fix', 'Change the mode of the alias files to "0644":

# chmod 0644 /etc/aliases /etc/aliases.db'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42762r662036_chk'
  tag severity: 'medium'
  tag gid: 'V-239529'
  tag rid: 'SV-239529r662038_rule'
  tag stig_id: 'VROM-SL-000550'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42721r662037_fix'
  tag 'documentable'
  tag legacy: ['SV-99179', 'V-88529']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
