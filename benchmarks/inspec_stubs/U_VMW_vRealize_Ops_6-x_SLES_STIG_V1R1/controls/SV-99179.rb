control 'SV-99179' do
  title 'The alias files must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the alias files may permit unauthorized modification. If an alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', 'Check the permissions of the alias files:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If the alias files have a mode more permissive than "0644", this is a finding.'
  desc 'fix', 'Change the mode of the alias files to "0644":

# chmod 0644 /etc/aliases /etc/aliases.db'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88529'
  tag rid: 'SV-99179r1_rule'
  tag stig_id: 'VROM-SL-000550'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
