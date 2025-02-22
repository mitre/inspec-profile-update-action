control 'SV-21743' do
  title 'The dual homed DISN core access circuits are NOT implemented such that each one can support the full bandwidth engineered for the enclave plus additional bandwidth to support surge conditions in time of crisis.'
  desc 'Providing dual homed access circuits from a C2 enclave to the DISN core is useless unless both circuits provide the same capacity to include enough overhead to support surge conditions. If one circuit is lost due equipment failure or facility damage, the other circuit must be able to carry the entire engineered load for a single circuit servicing the site. Additionally, the engineered capacity must take additional bandwidth into account to support higher levels of both data and VVoIP communications in time of crisis.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event dual homed DISN core access circuits are implemented as required to serve the enclave, ensure each circuit has the same capacity such that one is able to support the entire engineered bandwidth needs of the enclave.
NOTE: Each circuit must be engineered to include additional bandwidth to support higher levels of both data and VVoIP communications in time of crisis.

Determine if the site is dual homed via dual access circuits. Determine the size of both access circuits. Determine the engineered bandwidth needs for the enclave connection to the WAN.'
  desc 'fix', 'Ensure a bandwidth engineering study is performed to determine the WAN bandwidth needs for the site to include surge capacity.

Ensure each redundant DISN Core access circuit has the same capacity such that one is able to support the entire engineered bandwidth needs of the enclave.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19602'
  tag rid: 'SV-21743r1_rule'
  tag stig_id: 'VVoIP 6140 (DISN-IPVS)'
  tag gtitle: 'Deficient imp’n: C2 enclave; Dual Circuit Capacity'
  tag fix_id: 'F-20301r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'none'
  tag potential_impacts: 'Reduced availability and the inability to complete a C2 call'
end
