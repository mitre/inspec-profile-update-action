control 'SV-55749' do
  title 'The A/B, A/B/C, or A/B/C/D switch within an IP-based VTC system supporting conferences on multiple networks having different classification levels must be based on optical technologies to maintain electrical isolation between the various networks to which it connects.'
  desc 'The A/B, A/B/C, or A/B/C/D switch is physically connected to multiple networks having different classification levels. Copper-based switches provide minimal or no electrical isolation due to capacitance between the wires in the switch box and the switch contacts. This can permit information on one network to bleed or leak over to the other network, which can lead to the disclosure of classified information on a classified network to a network of lower classification. This must be prevented. Optical fiber is an insulator, thus it carries no electrical current and generates no electromagnetic field, eliminating the capacitance issue. As such, it provides excellent electrical isolation between the networks to which it connects.'
  desc 'check', 'Review A/B, A/B/C, or A/B/C/D switch vendor documentation to determine if optical technologies are used to maintain electrical isolation between the input port/connection and between all selectable output ports/connections. If this is not the case, this is a finding.
Validate approved equipment is being used. DISN Video Services (DVS) maintains a list of A/B, A/B/C, or A/B/C/D switches that have been certified to meet the above requirements at http://disa.mil/Services/Network-Services/Video/~/media/Files/DISA/Services/DVS/red_black_peripherals.xls.
If the A/B, A/B/C, or A/B/C/D switch is not on the list, this is a finding.'
  desc 'fix', 'Obtain and install an approved A/B, A/B/C, or A/B/C/D switch.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49177r5_chk'
  tag severity: 'medium'
  tag gid: 'V-43020'
  tag rid: 'SV-55749r1_rule'
  tag stig_id: 'RTS-VTC 7100'
  tag gtitle: 'RTS-VTC 7100 [IP]'
  tag fix_id: 'F-48604r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBCR-1'
end
