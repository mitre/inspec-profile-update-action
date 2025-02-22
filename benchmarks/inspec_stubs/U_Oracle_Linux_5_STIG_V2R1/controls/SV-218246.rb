control 'SV-218246' do
  title 'The root accounts home directory (other than /) must have mode 0700 or less permissive.'
  desc 'Permissions greater than 0700 could allow unauthorized users access to the root home directory.'
  desc 'check', 'Check the mode of the root home directory.

Procedure:
# find ~root -type d -prune -exec ls -ld {} \\;

If the home directory is /, this check will be marked "Not Applicable".

If the mode of the directory is not set to 0700 or less permissive, this is a finding.'
  desc 'fix', 'The root home directory will be configured to have permission set of 0700 or less permissive. Do not change the protections of the / directory. Use the following command to change protections for the root home directory: 

# chmod 0700 /rootdir.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19721r561422_chk'
  tag severity: 'medium'
  tag gid: 'V-218246'
  tag rid: 'SV-218246r603259_rule'
  tag stig_id: 'GEN000920'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19719r561423_fix'
  tag 'documentable'
  tag legacy: ['V-775', 'SV-64359']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
