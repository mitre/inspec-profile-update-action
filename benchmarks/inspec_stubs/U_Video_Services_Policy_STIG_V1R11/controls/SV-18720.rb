control 'SV-18720' do
  title 'Deficient VTU sleep mode configuration or operation.'
  desc 'Sleep mode is the power conservation and semi-disabled state that some VTUs can enter after being on standby for a period of time. While in sleep mode, the VTU is still minimally powered and thereby could be remotely accessed, managed, compromised, or easily activated. For the purpose of our discussions, sleep mode is different from standby mode by the fact that in standby mode, by our definition, the VTU is not actively participating in a call but is ready to receive or place a call. Sleep mode, is a semi off state whereby most functions of the VTU are disabled to conserve power. If used to mitigate vulnerabilities and not just conserve power, sleep mode must have the characteristics noted in this requirement.'
  desc 'check', '[IP][ISDN];  Interview the IAO to validate for CODEC compliance with the following requirement:

In the event sleep mode is to be used to mitigate standby vulnerabilities, ensure that sleep mode provides and/or is configured to provide the following functionality: 

- The CODEC’s audio and video pickup/transmission capability should be disabled as follows: 
   > Disable the microphone’s audio pickup capability. 
   > Disable the camera’s image capture capability. 
   > Disable remote activation/control capabilities of the camera and microphone. 
- Auto-answer capabilities are disabled. 
- Local user action is required to exit sleep mode such as pressing some button or key to activate the wakeup function. 
- If a wake-on-incoming-call feature is available, it must not fully wake the VTU and may only provide an indication that there is an incoming call along with meeting the incoming call display requirement below so that the user can make an informed decision to wake the system and answer the call or not. 
- In the event the VTU can be remotely accessed or managed during sleep mode, the following controls must be in place: 
   > The VTU must limit access to specific authorized IP addresses. 
   > Remote access must not permit the activation of the microphone and camera unless this functionality is required to meet validated, approved, and documented mission requirements. 

Note: If the VTU meets the user activation/authentication and banner requirements stated later, these function must be invoked when the VTU wakes. 

Note: If the VTU has a sleep mode, in addition to the required capabilities noted above, it should have configurable settings that permit immediate user activation via a button press and an automatic activation with a configurable time frame that could be as short as 15 seconds or as long as several hours, or never. This would permit the sleep mode to be used as partial or full mitigation for the vulnerabilities addressed by the above two requirements. The various configurable settings could be used when the VTU is in different locations. For example, the short duration and/or user activation could be used in a classified environment.

APL Testing: This is a finding in the event this requirement is not supported by the VTU.

Have the IAO or SA demonstrate the configuration setting required to meet the individual features of this requirement. 

Place the VTU in standby/sleep mode, place a call to the VTU, and view its responses.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Configure the VTU to provide the following functionality: 
- The CODEC’s audio and video pickup/transmission capability must be disabled as follows: 
   > Disable the microphone’s audio pickup capability. 
   > Disable the camera’s image capture capability. 
   > Disable remote activation/control capabilities of the camera and microphone. 
- Auto-answer capabilities are disabled. 
- Local user action is required to exit sleep mode such as pressing some button or key to activate the wakeup function. 
- If a wake-on-incoming-call feature is available, it must not fully wake the VTU and may only provide an indication that there is an incoming call along with meeting the incoming call display requirement below so that the user can make an informed decision to wake the system and answer the call or not. 
- In the event the VTU can be remotely accessed or managed during sleep mode, the following controls must be in place: 
   > The VTU must limit access to specific authorized IP addresses. 
   > Remote access must not permit the activation of the microphone and camera unless this functionality is required to meet validated, approved, and documented mission requirements. 

Note: If the VTU meets the user activation/authentication and banner requirements stated later, these function must be invoked when the VTU wakes. 

Note: If the VTU has a sleep mode, in addition to the required capabilities noted above, it should have configurable settings that permit immediate user activation via a button press and an automatic activation with a configurable time frame that could be as short as 15 seconds or as long as several hours, or never. This would permit the sleep mode to be used as partial or full mitigation for the vulnerabilities addressed by the above two requirements. The various configurable settings could be used when the VTU is in different locations. For example, the short duration and/or user activation could be used in a classified environment.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17593'
  tag rid: 'SV-18720r1_rule'
  tag stig_id: 'RTS-VTC 1027.00'
  tag gtitle: 'RTS-VTC 1027.00 [IP][ISDN]'
  tag fix_id: 'F-17511r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
