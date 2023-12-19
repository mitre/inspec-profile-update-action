control 'SV-18718' do
  title 'Deficient SOP or enforcement regarding how to power-off the VTU when it is not actively participating in a conference.'
  desc 'When the VTU is not active, it is best to power it off to mitigate its vulnerabilities. This may not be practical, particularly if the VTU is intended, or required, to receive un-scheduled incoming calls or is to be remotely managed and monitored in an un-scheduled manner. Receiving un-scheduled incoming calls that are automatically answered is, in itself, a vulnerability. This is an issue for IP and ISDN connected systems if auto-answer is on. The auto-answer feature is discussed later. Remote access and monitoring are also vulnerabilities due to the lack of strong access control mechanisms and the ease with which a VTU can be compromised if it is connected to an IP network. These vulnerabilities are discussed later. The point of this and the next requirement is to disable the capability of the VTU to “see and hear” information and activities located or occurring near the VTU when it is not actively participating in a call. While these vulnerabilities are of particular concern in an office or other work area, it may be of less concern in a conference room except if meetings occur in the facility that do not require the use of the VTC system.'
  desc 'check', '[IP][ISDN] Interview the IAO to validate compliance with the following requirement:

In the event the VTU is connected to an IP network and/or if auto-answer is on while connected to an ISDN network, ensure a policy and procedure is in place and enforced that requires users to power-off the VTU when it is not actively participating in a conference unless it is required to be powered-on to meet validated, approved, and documented mission requirements. 

Note: While this requirement can be deemed N/A or “Not a Finding” in the event there are validated, approved, and documented mission requirements, the VTU is still subject to RTS-VTC 1025.00. An example of a mission requirement needing validation, approval, and documentation would be a requirement for nightly testing of the VTU from a central location or a need to regularly answer incoming calls.  

Note: The documented and validated mission requirements along with their approval(s) are maintained by the IAO for inspection by auditors. Such approval is obtained from the DAA or IAM responsible for the VTU(s) or system. 

Note: This is not a requirement (i.e., N/A) if the VTU is located in a conference room that is only used for VTC conferences; the room is empty when not preparing for or participating in a VTC; the room contains no sensitive or classified information when not in use; no other meetings are held there; and no other work or activities occur there. 

Note: Sleep mode does not fully mitigate the vulnerability addressed here unless it can be invoked by the user. Typically a VTU would go to sleep after a period of time. During this period, the vulnerability still exists and may exist in sleep mode depending upon what is required to wake the VTU. Sleep mode should be able to be initiated by the user. Exiting sleep mode should be initiated by user action and not an automated process. This functionality needs to be explored further and specific requirements defined. 

Note: This requirement must be stated in user’s guides and training because the user is the one that must implement these mitigations.

Inspect the SOP as well as user training materials, agreements, and guides to determine if the requirement is adequately covered. Interview the IAO to determine how the SOP is enforced. Interview a sampling of users to determine their awareness and implementation of the requirement and whether the SOP is enforced. Have a sampling of users demonstrate how to power-off the VTU when it is not actively participating in a conference. This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.  Have a sampling of users demonstrate how to power-off the VTU when it is not actively participating in a conference.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Define and enforce policy and procedure that when a VTU is connected to an IP network and/or if auto answer is on while connected to an ISDN network that the user is required and knows how to power-off the VTU when it is not actively participating in a conference unless it is required to be powered-on to meet validated, approved, and documented mission requirements. 

Provide user training regarding this SOP and include it in user agreements and user guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17591'
  tag rid: 'SV-18718r1_rule'
  tag stig_id: 'RTS-VTC 1020.00'
  tag gtitle: 'RTS-VTC 1020.00 [IP][ISDN]'
  tag fix_id: 'F-17509r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This can be deemed N/A or “Not a Finding” in the event there are validated, approved, and documented mission requirements; however, the VTU is still subject to RTS-VTC 1025.00. An example of a mission requirement needing validation, approval, and documentation would be a requirement for nightly testing of the VTU from a central location or a need to regularly answer incoming calls.

This is N/A if the VTU is located in a conference room that is only used for VTC conferences the room is empty when not preparing for or participating in a VTC; the room contains no sensitive or classified information when not in use; no other meetings are held there; and no other work or activities occur there.'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
