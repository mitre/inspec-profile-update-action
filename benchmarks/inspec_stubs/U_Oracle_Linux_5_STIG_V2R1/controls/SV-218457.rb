control 'SV-218457' do
  title 'The at.deny file must not be empty if it exists.'
  desc 'On some systems, if there is no at.allow file and there is an empty at.deny file, then the system assumes everyone has permission to use the "at" facility.  This could create an insecure setting in the case of malicious users or system intruders.'
  desc 'check', '# more /etc/at.deny
If the at.deny file exists and is empty, this is a finding.'
  desc 'fix', 'Add appropriate users to the at.deny file, or remove the empty at.deny file if an at.allow file exists.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19932r562528_chk'
  tag severity: 'medium'
  tag gid: 'V-218457'
  tag rid: 'SV-218457r603259_rule'
  tag stig_id: 'GEN003300'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19930r562529_fix'
  tag 'documentable'
  tag legacy: ['V-985', 'SV-64371']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
