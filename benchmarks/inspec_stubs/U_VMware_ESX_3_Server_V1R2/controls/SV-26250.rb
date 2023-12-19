control 'SV-26250' do
  title 'A root kit check tool must be run on the system at least weekly.'
  desc 'Root kits are software packages designed to conceal the compromise of a system from the SA. Root kit checking tools examine a system for evidence that a root kit is installed. Dedicated root kit detection software or root kit detection capabilities included in anti-virus packages may be used to satisfy this requirement.'
  desc 'check', 'Ask the SA if a root kit check tool is run on the system weekly. If this is not performed, this is a finding.'
  desc 'fix', 'Create an automated job or establish a site-defined procedure to check the system weekly with a root kit check tool.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29315r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22575'
  tag rid: 'SV-26250r1_rule'
  tag stig_id: 'GEN008380'
  tag gtitle: 'GEN008380'
  tag fix_id: 'F-26347r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
