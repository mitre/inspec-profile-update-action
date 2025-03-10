control 'SV-18723' do
  title 'Deficient SOP for, enforcement, usage, or configuration of the auto-answer feature.'
  desc 'In the event the auto-answer feature is approved for use or cannot be administratively disabled and thus is available for users to activate, several mitigating requirements must be met. The first of these is that the user(s) to which the feature is available must be trained in its proper use and in the vulnerabilities it presents because the user is the one that must implement the operational mitigations. The second is the VTU must answer the call with the microphone muted and with the camera covered or disabled. This will prevent an ongoing conversation from being heard and room activities seen by the caller. This will also prevent the room from being audibly and visually monitored if a call is automatically answered when the VTU is un-attended. The third mitigating requirement is that the user must be notified that the VTU has received and answered a call such that the user may be viewed if the camera is not/cannot be covered or listened to if the microphone is not/cannot be muted. This means that a noticeable visual indication must be provided and any available audible signal must be maintained at an audible level so that it can be heard.'
  desc 'check', '[IP][ISDN];  Interview the IAO to validate compliance with the following requirement:

In the event the auto-answer feature is available and/or used, ensure a policy and procedure is in place and enforced such that, all of the following occurs: 

- The auto-answer feature is configured to answer with the microphone muted. 
- The camera is covered or otherwise disabled while waiting for a call. 
- The VTU provides a visual indication that a call has been answered. 
- The user will ensure the ringer or audible notification volume is set to an easily audible level or the VTU will automatically satisfy this requirement.
- The user(s) to which the feature is available is trained in its proper use as reflected in the SOP and in the vulnerabilities it presents. 

Note: During APL testing, this is a finding in the event “auto-answer with microphone muted” is not configurable on the VTU. It is also desirable that this setting will ensure the audible notification is at a level to be easily heard.

Determine if this requirement is covered in a SOP and user training/agreements. Interview a sampling of users to determine their awareness and implementation of the requirement. Verify that, if supported, the VTU auto-answer feature is configured to answer with microphone muted.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
In the event the auto-answer feature is approved for use, perform the following tasks:
- Maintain full documentation on the validation of the mission requirement and the DAA approval to use the auto-answer feature
- Develop and enforce a SOP regarding the proper use of the auto-answer feature. 
- Configure the auto-answer feature to answer with the microphone muted. 
- Ensure the camera is covered by the user or otherwise disabled automatically while waiting for a call. 
- Ensure the VTU provides a visual indication that a call has been answered. 
- Train users to ensure the ringer or audible notification volume is set and maintained at an easily audible level or the VTU automatically satisfies this requirement.
- Train the user(s) to which the feature is available in its proper use as reflected in the SOP and in the vulnerabilities it presents.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18896r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17596'
  tag rid: 'SV-18723r1_rule'
  tag stig_id: 'RTS-VTC 1060.00'
  tag gtitle: 'RTS-VTC 1060.00 [IP][ISDN]'
  tag fix_id: 'F-17514r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
  tag ia_controls: 'DCBP-1, DCSD-1, ECSC-1'
end
