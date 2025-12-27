control 'SV-17556' do
  title 'Administrative sessions with the VTU do not timeout within a maximum of 15 minutes.'
  desc 'An established and/or open configuration/administration (user or administrator) session that is inactive, idle, or unattended is an avenue for unauthorized access to the management port/interface of the VTU. This can lead to compromise of the system’s/device’s configuration and/or denial of service. Idle sessions can be caused simply by a user or administrator being distracted or diverted from a configuration/administration session/task or by forgetting to log out of the management session when finished with his/her tasks. To ensure that the capability for unauthorized access in the event of an idle/inactive session is mitigated; an idle/inactive session timeout/logout capability must exist and be used. The timeout duration must be configurable to adjust for changing policies and requirements. Typically this duration should be set for 15 minutes as a maximum; however it can be shortened for tighter security. This requirement applies to all types of local and remote management connections/sessions and all management session protocols.

While not specifically related to VTC, this requirement can work against or inhibit certain management functions. System/device configuration backups or software upgrades requiring file transfers may exceed the idle timeout duration. In this case, the operation might fail if the idle timer disconnected the session midway through. During such events, the idle timer should recognize this activity as the session not being idle. Alternately, the idle timer duration may be extended or may be disabled as long as it is re-enabled/reset after the file transfer. Another management function that can be inhibited by an idle session timeout is when a session is required to be established for the continuous monitoring of the system/device. In this case, the idle timer may be disabled as long as it is re-enabled after the monitoring is no longer needed.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

Ensure a configurable “idle/inactive session timeout/logout feature” is available and used to disconnect idle/inactive management connections or sessions. The idle timer is set to a maximum of 15 minutes. Longer time periods are documented and approved by the responsible DAA. This requirement applies to all types of physical and logical management connections and all management session protocols.

NOTE 1: This is not a finding in the event an approved management connection/session must be established for permanent full time monitoring of a system/device or the production traffic it processes. 

NOTE 2: This is not a finding during management operations where the disconnection of the connection/session due to idle session timeout would inhibit the successful completion of a management task. A SOP must be established and enforced, or an automated process used, to ensure the idle/inactive session timeout feature is re-enabled and reset following such activity

NOTE 3:  During APL testing, this is a finding in the event this requirement is not supported by the VTU.

> Determine if a configurable “idle/inactive session timeout/logout feature” is available and used to disconnect idle/inactive management connections or sessions.  
> Determine if the timeout is set to a maximum of 15 minutes. 
> If the timeout is set to a longer period, determine if the extended time period is documented and approved by the responsible DAA and a SOP is in place and enforced that will insure that the idle/inactive session timeout feature is re-enabled and reset following monitoring/testing activity.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks: 
> Implement a VTU with a configurable “idle/inactive session timeout/logout feature” for management sessions.
> Configure/set the idle timer to a maximum of 15 minutes.
> If longer periods are necessary, obtain approval from the responsible DAA. Document approval for inspection by auditors. Develop and enforce a SOP that will insure that the idle/inactive session timeout feature is re-enabled and reset following monitoring/testing activity. Include this SOP in administrator training, agreements and guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17356r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16557'
  tag rid: 'SV-17556r1_rule'
  tag stig_id: 'RTS-VTC 2325.00'
  tag gtitle: 'RTS-VTC 2325.00 [IP][ISDN]'
  tag fix_id: 'F-16526r1_fix'
  tag 'documentable'
  tag mitigations: 'RTS-VTC 2325.00'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Access to the VTU by unauthorized individuals possibly leading to the disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag mitigation_control: 'N/A'
  tag responsibility: ['Designated Approving Authority', 'Information Assurance Officer', 'System Administrator']
end
