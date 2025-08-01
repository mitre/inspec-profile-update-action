control 'SV-18725' do
  title 'Deficient SOP or enforcement regarding handling of incoming calls while in a conference.'
  desc 'Whether active or inactive, a VTU must display the source of an incoming call and the caller’s identity so that the user can decide to answer the call or not. This decision must also be based upon what information would be made available to the caller when call is answered. The information that would be placed at risk is what can be picked up in the physical area of the VTU or what is being carried by the conference in which it is participating. 

If the VTU is participating in a conference already, answering a call while in a conference would activate the VTU’s integrated MCU and join the caller to the conference. The possibility of an incoming call being automatically joined to a meeting in progress in this manner places the confidentiality of that meeting at risk. The caller could become a participant of a meeting to which they were not invited and subsequently receive sensitive or classified information for which the caller may or may not have a need-to-know or appropriate security clearance.

As with a VTU in standby mode, an “auto-answer” feature is of great concern during a VTC session. A VTU must be configured in such a way that it cannot automatically answer a call and join the call to an active session without some form of access control. Either user intervention or a properly managed “local meeting” password is required to join such an incoming call to an active session. In some instances the “do-not-disturb” feature may be used by the user to block such calls by returning a “busy” signal. The capability of joining a conference on a VTU using its integrated MCU through the use of a “local meeting” password must be used only when the VTU user needs to pre-schedule and host a multipoint conference on his/her VTU. This capability must not be available at all times. The VTU should have the capability to disable this kind of access when it is not needed. Local meeting passwords must be used one time and not repeated. This requirement is discussed later.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:
	
Ensure the following regarding incoming calls while the VTU is engaged in a conference: 

- The VTU automatically rejects incoming calls, is administratively configured to return a “busy signal”, or optionally does so through the use of a user selected “do-not-disturb” feature. 
OR 
- The VTU is configured to not automatically answer an incoming call and join it to an active conference (in progress) without user intervention. (i.e., the user must decide to answer the call or not based on the required source and caller information display. Answering the call affects the join). 
OR 
- A password, entered by the caller, is required to access the VTU’s integrated MCU. This password must be unique among all other passwords used by the system. This capability must not be functional at all times, i.e., it is only to be functional when the capability is required to be used. 

Note: In the event the VTU supports the “call-in/join via local meeting password” feature for the integrated MCU, the VTU should also have an administrative setting that disables this capability thereby forcing host action. In effect this setting would invoke an automatic “do-not-disturb” or return of a “busy” signal while the VTU is active. 
The various VTC vendors implement VTU integrated MCU access control differently. 

Examples are as follows: 
Tandberg – Dial out and dial in with host action only – no local meeting password option. 
Polycom – Dial-out and Dial-in w/ “meeting password” which is required to join a multipoint call or streamed meeting. This is a memory location used to set the local MCU or streamed media access or join password for access to the VTU and to set the endpoint password given to another MCU when calling into it. “This field can also be used to store a password required by another system that this system calls.” 

Note: this pre-configurable “meeting password” violates unique and scripted password policies. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU as an administrator configurable option and/or as a default condition. The desired capability is to block incoming calls during a VTC session by default without requiring the user to set the condition since the user may forget to do so. The user may have the capability to set the condition that temporarily turns off the “do-not-disturb” feature such that the call can be answered externally to the conference and then manually joined.

Interview the IAO to determine if this requirement is covered in a SOP and user training/agreements. Interview a sampling of users to determine their awareness and implementation of the requirement. Place a call to an endpoint that is already in a conference and witness its response or reaction.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:

Ensure the following regarding incoming calls while the VTU is engaged in a conference: 

- The VTU automatically rejects incoming calls, is administratively configured to return a “busy signal”, or optionally does so through the use of a user selected “do-not-disturb” feature. 
AND/OR 
- The VTU is configured to not automatically answer an incoming call and join it to an active conference (in progress) without user intervention. (i.e., the user must decide to answer the call or not based on the required source and caller information display. Answering the call affects the join.) 
AND/OR 
- A password, entered by the caller, is required to access the VTU’s integrated MCU. This password must be unique among all other passwords used by the system. This capability must not be functional at all times, i.e., it is only to be functional when the capability is required to be used.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18898r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17598'
  tag rid: 'SV-18725r1_rule'
  tag stig_id: 'RTS-VTC 1140.00'
  tag gtitle: 'RTS-VTC 1140.00 [IP][ISDN]'
  tag fix_id: 'F-17516r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Other']
end
