control 'SV-35061' do
  title 'The system must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'check', "Search for any .forward files (typically found in a user's  home directory) on the system by:
# find / -type f -name .forward 

This is considered a finding if any .forward files are found on the system."
  desc 'fix', 'Remove .forward files from the system.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4385'
  tag rid: 'SV-35061r1_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'GEN004580'
  tag fix_id: 'F-31939r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
