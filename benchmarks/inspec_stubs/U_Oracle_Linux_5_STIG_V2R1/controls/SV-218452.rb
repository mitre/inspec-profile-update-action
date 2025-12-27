control 'SV-218452' do
  title 'The at.deny file must have mode 0600 or less permissive.'
  desc 'The "at" daemon control files restrict access to scheduled job manipulation and must be protected.  Unauthorized modification of the at.deny file could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/at.deny
If the file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the file.
# chmod 0600 /etc/at.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19927r562513_chk'
  tag severity: 'medium'
  tag gid: 'V-218452'
  tag rid: 'SV-218452r603259_rule'
  tag stig_id: 'GEN003252'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19925r562514_fix'
  tag 'documentable'
  tag legacy: ['V-22392', 'SV-64355']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
