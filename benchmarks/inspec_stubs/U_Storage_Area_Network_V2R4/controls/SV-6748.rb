control 'SV-6748' do
  title 'A current drawing of the site’s SAN topology that includes all external and internal links, zones, and all interconnected equipment is not being maintained.'
  desc 'A drawing of the SAN topology gives the IAO and other interested individuals a pictorial representation of the SAN.  This can be helpful in diagnosing potential security problems.
The IAO/NSO will maintain a current drawing of the site’s SAN topology that includes all external and internal links, zones, and all interconnected equipment.'
  desc 'check', 'The reviewer will interview the IAO/NSO and view the drawings supplied to verify that a current drawing of the site’s SAN topology that includes all external and internal links, zones, and all interconnected equipment.'
  desc 'fix', 'Create drawing of the site’s SAN topology that includes all external and internal links, zones, and all interconnected equipment.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2481r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6628'
  tag rid: 'SV-6748r1_rule'
  tag stig_id: 'SAN04.007.00'
  tag gtitle: 'SAN Topology Drawing'
  tag fix_id: 'F-6217r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'DCHW-1'
end
