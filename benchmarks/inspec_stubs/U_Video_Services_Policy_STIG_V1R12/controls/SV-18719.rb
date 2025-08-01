control 'SV-18719' do
  title 'Deficient SOP or enforcement for microphone and camera disablement when the VTU is required to be powered and inactive (in standby).'
  desc 'In the event that mission requirements dictate the VTU be in a powered-on state when inactive (thereby making RTS-VTC 1020 N/A or “Not a Finding”), other measures are required to mitigate the vulnerability of possible VTU compromise and establish a defense in depth posture. These mitigations are, 1 - to mute the microphone and 2 – to disable the viewing capability of the camera in some manner. If the camera is movable, it could be aimed at the nearest corner of the room; however, this is no mitigation if the VTU is compromised or remotely controlled and the camera can be re-aimed into the room. The best mitigation for the camera is to cover the lens of the camera.  This is applicable to both movable and fixed cameras.'
  desc 'check', '[IP][ISDN] Interview the IAO to validate compliance with the following requirement:

In the event the VTU is connected to an IP network and/or if auto-answer is on while connected to an ISDN network, AND the VTU is required to be powered-on to meet validated, approved, and documented mission requirements (that is RTS-VTC 1025.00 is “not a finding”); ensure a policy and procedure is in place and enforced that requires users to perform the following when the VTU is it is not actively participating in a conference: 
Mute the microphone. 
   AND
Disable the capability of the camera to view activities within the room as follows:
   Cover the camera(s) if its/their position/aim is fixed or able to be remotely controlled.
     OR
Aim the camera(s) at a nearby corner where it/they cannot see room activities if the camera position/aim is movable but cannot be remotely controlled. 

Note: The documented and validated mission requirements along with their approval(s) are maintained by the IAO for inspection by auditors. Such approvals are obtained from the DAA or IAM responsible for the VTU(s) or system. This documentation and validated mission requirements are the same documentation that renders RTS-VTC 1020.00 N/A or “Not a Finding”

Note: This finding can be reduced to a CAT III in the event the camera(s) can be remote controlled but are aimed at the wall (e.g., a corner) where it/they cannot see room activities if the camera supports aiming or being moved. While the practice of aiming the camera at the side or back wall of the room where there is nothing to see and muting the microphone can mitigate normal operational issues, this measure is not a mitigation if the camera can be remotely controlled via auto-answer and Far End Camera Control (FECC) and/or the CODEC remote control/configuration feature is not configured properly, is compromised, or can be accessed by a administrator with the remote access password.

Note: This is not a finding in the event sleep mode provides the necessary disablement functions and is invoked by the user when the VTU is powered on or leaves the active state. This finding can be reduced to a CAT III finding in the event sleep mode provides the necessary disablement functions and the VTU enters sleep automatically within 15 minutes of when the VTU entered standby. This is still a finding because the vulnerability exists during the standby period. 

Note: This is not a requirement (i.e., N/A) if the VTU is located a conference room that is only used for VTC conferences; the room is empty when not preparing for or participating in a VTC; the room contains no sensitive or classified information when not in use; no other meetings are held there; and no other work or activities occur there.
 
Note:  A camera cover should be provided by the camera vendor and attached in such a manner that it is not easily detachable so that it cannot be easily lost. Alternately, the cover can be as simple as an opaque cloth of appropriate size or sewn such that it won’t fall off easily. If the cover is detachable such that can be easily lost, a supply of replacement covers should be readily available.

Note: This requirement must be stated in site user’s guides and training because the user is the one that must implement these mitigations.

Inspect the SOP as well as user training materials, agreements, and guides to determine if the items in the requirement are adequately covered. Interview the IAO to determine how the SOP is enforced. Interview a sampling of users to determine their awareness and implementation of the requirement and whether the SOP is enforced. This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.

This is a finding if the VTU is found to be powered-on when inactive and the microphone and/or camera are not disabled.

This is a finding if there is no documented requirement that the VTU be powered-on or there are no approvals. Inspect the documentation relating to the DAA approvals for the validated, approved, and documented mission requirements that require the VTU to be powered-on while inactive. 

This is a finding if there is no SOP regarding the disablement of the VTU microphone and camera when the VTU is not actively participating in a conference. Interview the IAO to determine if this requirement is covered in a SOP and user training/agreements. Interview a sampling of users to determine their awareness and implementation of the requirement.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:  
Define and enforce policy and procedure that when a VTU is connected to an IP network and/or if auto answer is on while connected to an ISDN network AND the VTU is required to be powered-on to meet validated, approved, and documented mission requirements., that the user is required and knows how to disable the VTU microphone and camera when the VTU is not actively participating in a conference. 

Provide user training regarding this SOP and include it in user agreements and user guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18892r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17592'
  tag rid: 'SV-18719r1_rule'
  tag stig_id: 'RTS-VTC 1025.00'
  tag gtitle: 'RTS-VTC 1025.00 [IP][ISDN]'
  tag fix_id: 'F-17510r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
  tag ia_controls: 'DCBP-1, DCSD-1, ECSC-1, PEDI-1'
end
