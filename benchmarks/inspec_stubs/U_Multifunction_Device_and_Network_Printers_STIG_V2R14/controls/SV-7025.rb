control 'SV-7025' do
  title 'MFDs with print, copy, scan, or fax capabilities must be prohibited on classified networks without the approval of the DAA.'
  desc 'MFDs with print, copy, scan, or fax capabilities, if compromised, could lead to the compromise of classified data or the compromise of the network.  The IAO will ensure MFDs with copy, scan, or fax capabilities are not allowed on classified networks unless approved by the DAA.'
  desc 'check', 'The reviewer will interview the IAO to verify that MFDs with print, copy, scan, or fax capabilities are prohibited on classified networks unless approved by the DAA.'
  desc 'fix', 'Remove the MFD from the classified network until DAA approval is obtained.'
  impact 0.7
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3012r4_chk'
  tag severity: 'high'
  tag gid: 'V-6800'
  tag rid: 'SV-7025r2_rule'
  tag stig_id: 'MFD07.001'
  tag gtitle: 'MFD Classified Network'
  tag fix_id: 'F-6472r4_fix'
  tag 'documentable'
  tag potential_impacts: 'If the device is removed from the classified network it will need to be sanitized in accordance with DoDD 5200.1R if it is to be used for unclassified processing or is to be decommissioned.'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCBP-1'
end
