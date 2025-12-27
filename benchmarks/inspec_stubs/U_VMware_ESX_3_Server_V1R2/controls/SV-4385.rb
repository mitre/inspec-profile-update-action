control 'SV-4385' do
  title 'The system must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'check', 'Search for any .forward files on the system.

# find / -name .forward -print

This is considered a finding if any .forward files are found on the system.'
  desc 'fix', 'Remove .forward files from the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8268r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4385'
  tag rid: 'SV-4385r2_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'GEN004580'
  tag fix_id: 'F-4296r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
