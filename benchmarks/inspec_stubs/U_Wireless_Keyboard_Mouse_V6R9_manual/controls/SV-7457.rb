control 'SV-7457' do
  title 'If infrared wireless mice and keyboards are used on classified or unclassified equipment and networks, the required conditions must be followed.'
  desc 'Wireless mice and keyboard receivers are a open wireless port on a PC, which can be attacked by a hacker.  In addition, wireless keyboard transmissions, if not secured, can be compromised when intercepted.'
  desc 'check', 'Detailed Policy Requirements:

If infrared wireless mice and keyboards are used on classified or unclassified equipment and networks, the following conditions must be followed:

­- The DAA, in consultation with the CTTA, has approved IR wireless mice and/or keyboards for use in the facility.  (The CTTA should evaluate the TEMPEST risks of the system.)
­- When wireless mice and/or keyboards are used on classified equipment, the area is approved for processing classified information at the appropriate level.
­- The area is totally enclosed with walls, ceiling, and floor consisting of material opaque to IR. There are no windows unless each window is covered with a film approved for blocking IR. All doors will remain closed when the devices are in operation.
­- There is no mixing of classified and unclassified equipment using IR within the same enclosed area. 
­- When IR is used with classified equipment in the same enclosed area as unclassified equipment with IR ports, the IR ports on the unclassified equipment is completely covered with metallic tape.
­- When IR is used with unclassified equipment in the same enclosed area as classified equipment with IR ports, the IR ports on the classified equipment is completely covered with metallic tape. 

Check Procedures:

Review documentation.
1. Verify the IR device is DAA approved and in compliance with CTTA separation requirements.  
2. Visually and electronically survey the area to test if emanations from the IR device is transmitting beyond the allowed area as per CTTA (or ask for documentation showing that this testing has be done).  
3. Verify the policy requirements listed in the policy above are in place and users are trained on the requirements by interviewing the SM or IAO.
Mark as a finding if any of these requirements are not met.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target Wireless Peripheral'
  tag check_id: 'C-4010r1_chk'
  tag severity: 'medium'
  tag gid: 'V-7073'
  tag rid: 'SV-7457r1_rule'
  tag stig_id: 'WIR0530'
  tag gtitle: 'Infrared keyboards and mice'
  tag fix_id: 'F-19294r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end
