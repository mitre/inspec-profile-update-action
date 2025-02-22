control 'SV-218469' do
  title 'The at.deny file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.deny file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /etc/at.deny
If the at.deny file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the owner of the at.deny file.
# chown root /etc/at.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19944r562561_chk'
  tag severity: 'medium'
  tag gid: 'V-218469'
  tag rid: 'SV-218469r603259_rule'
  tag stig_id: 'GEN003480'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19942r562562_fix'
  tag 'documentable'
  tag legacy: ['V-4368', 'SV-64417']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
