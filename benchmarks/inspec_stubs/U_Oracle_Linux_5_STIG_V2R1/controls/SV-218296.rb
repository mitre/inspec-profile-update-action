control 'SV-218296' do
  title 'The /etc/group file must be owned by root.'
  desc 'The /etc/group file is critical to system security and must be owned by a privileged user.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify the /etc/group file is owned by root.

# ls -l /etc/group

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/group file to root.

# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19771r561677_chk'
  tag severity: 'medium'
  tag gid: 'V-218296'
  tag rid: 'SV-218296r603259_rule'
  tag stig_id: 'GEN001391'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19769r561678_fix'
  tag 'documentable'
  tag legacy: ['V-22335', 'SV-64561']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
