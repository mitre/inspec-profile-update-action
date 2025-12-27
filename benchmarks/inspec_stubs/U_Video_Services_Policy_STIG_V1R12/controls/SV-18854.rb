control 'SV-18854' do
  title 'Inadequate notification to conference participants (manual or automatic) of monitoring activity by someone that is not a direct participant in a VTC session/conference.'
  desc 'Monitoring of a conference or VTC system can be performed in various ways. This can be by accessing the monitoring capabilities of a particular VTU via IP as discussed above, or using a capability of a centralized MCU, or an administrator or “operator/facilitator” can participate in a conference using a VTU. No matter how monitoring is being performed, participants in a call must be notified or be made aware that the call is being monitored by someone that is not a direct participant of the call or conference who therefore may not have a need-to-know regarding the conference information. This is a particular concern if the monitored conference contains classified information. If the monitoring is done by remotely accessing a VTU, typically, an automated notification is displayed on the VTU being monitored. This indication should also be displayed on all connected endpoints. Minimally, there is a SOP that requires the presence of a person monitoring a conference be announced to the conferees. 

Note: This can minimally be accomplished via the enforcement of a SOP whereby the person performing the monitoring notifies the conference of their presence. Alternately, if an automated monitoring indicator is displayed on one VTU, the SOP must require that the participant or conferee seeing the indication announce the monitoring activity to the conference unless the indication appears on all participating endpoints.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

Ensure conference participants are made aware that a conference is being monitored by someone that is not a direct participant of the call or conference. 

Interview the IAO to determine if this requirement is covered by an automatic indicator that appears on all participating endpoints OR is covered in a SOP and user training/agreements. Interview the IAO and monitoring “operator/facilitator” to determine their awareness and implementation of the requirement.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
- Configure the CODEC and/or MCU to automatically display an indication on all endpoints participating in a conference that the conference is being monitored.
OR
- Develop a SOP that addresses manual notification by SAs and chair persons that the conference is being monitored.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18950r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17680'
  tag rid: 'SV-18854r1_rule'
  tag stig_id: 'RTS-VTC 1164.00'
  tag gtitle: 'RTS-VTC 1164.00 [IP][ISDN]'
  tag fix_id: 'F-17577r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a SA that is monitoring a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1, PEDI-1'
end
