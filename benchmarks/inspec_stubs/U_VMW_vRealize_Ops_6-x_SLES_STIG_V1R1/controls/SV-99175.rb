control 'SV-99175' do
  title 'The alias files must be owned by root.'
  desc 'If the alias and aliases.db files are not owned by root, an unauthorized user may modify the file to add aliases to run malicious code or redirect email.'
  desc 'check', 'Check the ownership of the alias file:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If all the files are not owned by "root", this is a finding.'
  desc 'fix', 'Change the owner of the alias files to "root":

# chown root /etc/aliases
# chown root /etc/aliases.db'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88525'
  tag rid: 'SV-99175r1_rule'
  tag stig_id: 'VROM-SL-000540'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95267r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
