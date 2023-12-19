control 'SV-218462' do
  title 'The at directory must have mode 0755 or less permissive.'
  desc 'If the "at" directory has a mode more permissive than 0755, unauthorized users could be allowed to view or to edit files containing sensitive information within the "at" directory.  Unauthorized modifications could result in Denial of Service to authorized "at" jobs.'
  desc 'check', 'Check the mode of the "at" directory.

Procedure:
# ls -ld /var/spool/at

If the directory mode is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the "at" directory to 0755.

Procedure:
# chmod 0755 <at directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19937r562543_chk'
  tag severity: 'medium'
  tag gid: 'V-218462'
  tag rid: 'SV-218462r603259_rule'
  tag stig_id: 'GEN003400'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19935r562544_fix'
  tag 'documentable'
  tag legacy: ['V-4364', 'SV-64287']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
