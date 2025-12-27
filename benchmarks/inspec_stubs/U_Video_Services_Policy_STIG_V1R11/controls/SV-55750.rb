control 'SV-55750' do
  title 'An IP-based VTC system implementing a single CODEC supporting conferences on multiple networks having different classification levels must be implemented in a manner such that configuration information for a network having a higher classification level is not disclosed to a network having a lower classification level.'
  desc 'Connecting the CODEC to a network while it is being reconfigured could lead to the disclosure of sensitive configuration information for a network having a higher classification level to a network having a lower classification level. Ideally, the CODEC will be disconnected from any network while it is being reconfigured. However, the requirement can be met by using a procedure that purges the configuration for the currently connected network, power cycling the CODEC as required (for a minimum of 60 seconds per another requirement) as the CODEC is switched to the next network, then reconfigures the CODEC for the next session.'
  desc 'check', 'Review the VTC system architecture documentation and observe system operation while transitioning between networks to verify one of the following:
• The CODEC is switched to a disconnected/unused switch position while it is being purged/reconfigured .
• The CODEC is purged while connected to one network, then power cycled as it is switched to the next network, then reconfigured for that network. 
• Alternately, if a manual switching procedure is used, ensure the CODEC is physically disconnected from any network while being reconfigured. 
If none of these procedures is being followed, this is a finding.'
  desc 'fix', 'Architect, implement, and configure the system such that the A/B, A/B/C, or A/B/C/D switch connects the CODEC to an unused switch position while it is being reconfigured during transition from one network to another.
OR
Architect, implement, and configure the system such that the CODEC configuration is purged before it is switched to the next network, then the CODEC is power cycled for the required time period as the A/B, A/B/C, or A/B/C/D switch connects the CODEC to the next network, then the CODEC is reconfigured for that network.
OR 
If a manual switching procedure is used, physically disconnect the CODEC from any network while it is reconfigured for the next network.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49178r4_chk'
  tag severity: 'medium'
  tag gid: 'V-43021'
  tag rid: 'SV-55750r1_rule'
  tag stig_id: 'RTS-VTC 7120'
  tag gtitle: 'RTS-VTC 7120 [IP]'
  tag fix_id: 'F-48605r8_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBCR-1'
end
