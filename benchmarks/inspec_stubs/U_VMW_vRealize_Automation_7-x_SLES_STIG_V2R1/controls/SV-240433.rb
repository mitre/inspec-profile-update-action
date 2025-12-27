control 'SV-240433' do
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
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43666r671038_chk'
  tag severity: 'medium'
  tag gid: 'V-240433'
  tag rid: 'SV-240433r671040_rule'
  tag stig_id: 'VRAU-SL-000560'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43625r671039_fix'
  tag 'documentable'
  tag legacy: ['SV-100293', 'V-89643']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
