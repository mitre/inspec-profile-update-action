control 'SV-227646' do
  title 'The /etc/group file must have mode 0644 or less permissive.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the mode of the /etc/group file.

Procedure:
# ls -l /etc/group
If the file mode is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/group file to 0644 or less permissive.
# chmod 0644 /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29808r488498_chk'
  tag severity: 'medium'
  tag gid: 'V-227646'
  tag rid: 'SV-227646r603266_rule'
  tag stig_id: 'GEN001393'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29796r488499_fix'
  tag 'documentable'
  tag legacy: ['V-22337', 'SV-26433']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
