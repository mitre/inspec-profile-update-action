control 'SV-4509' do
  title 'The CSS DNS does not transmit APP session data over an out-of-band network if one is available.'
  desc 'One can also limit APP communication to an out of band network, which would make it considerably more difficult for adversaries to spoof the addresses of peers or hijack APP sessions.'
  desc 'check', 'In the presence of the reviewer, the CSS DNS administrator should enter the following command while in global configuration mode:

show app session

Instruction:  Ensure Application Peering Protocol (APP) session data is not sent over an out-of-band network.  If APP session data is sent over an out-of-band network, then this is a finding.'
  desc 'fix', 'The CSS DNS administrator should use the following command while in global configuration mode; app session 1.2.3.4 (sample IP address), to configure CSS to only transmit session data over an out-of-band network, if one is available.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3422r1_chk'
  tag severity: 'low'
  tag gid: 'V-4509'
  tag rid: 'SV-4509r1_rule'
  tag stig_id: 'DNS0920'
  tag gtitle: 'The CSS DNS does not transmit APP session OOB.'
  tag fix_id: 'F-4394r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
