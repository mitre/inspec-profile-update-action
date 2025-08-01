control 'SV-218298' do
  title 'The /etc/group file must have mode 0644 or less permissive.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the mode of the /etc/group file.

# ls -l /etc/group

If the file mode is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/group file to 0644 or less permissive.

# chmod 0644 /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19773r561683_chk'
  tag severity: 'medium'
  tag gid: 'V-218298'
  tag rid: 'SV-218298r603259_rule'
  tag stig_id: 'GEN001393'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19771r561684_fix'
  tag 'documentable'
  tag legacy: ['V-22337', 'SV-64565']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
