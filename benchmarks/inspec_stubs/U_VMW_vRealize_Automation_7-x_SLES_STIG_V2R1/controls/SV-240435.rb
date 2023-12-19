control 'SV-240435' do
  title 'The alias files must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the alias files may permit unauthorized modification. If an alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', 'Check the permissions of the alias files:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If the files have a mode more permissive than "0644", this is a finding.'
  desc 'fix', 'Change the mode of the alias files to "0644":

# chmod 0644 /etc/aliases /etc/aliases.db'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43668r671044_chk'
  tag severity: 'medium'
  tag gid: 'V-240435'
  tag rid: 'SV-240435r671046_rule'
  tag stig_id: 'VRAU-SL-000570'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43627r671045_fix'
  tag 'documentable'
  tag legacy: ['SV-100297', 'V-89647']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
