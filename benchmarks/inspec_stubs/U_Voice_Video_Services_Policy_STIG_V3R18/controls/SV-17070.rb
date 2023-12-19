control 'SV-17070' do
  title 'Audio pickup or video capture capabilities (microphones and cameras) are not disabled when not needed for active participation in a communications session.'
  desc 'The VTC STIG discusses the possibility of undesired or improper viewing of and/or listening to activities and conversations in the vicinity of a hardware based VTC endpoint, whether it is a conference room system or an office based executive or desktop system. If this was to occur, there could be inadvertent disclosure of sensitive or classified information to individuals without the proper clearance or need-to-know. This vulnerability could occur if the endpoint was set to automatically answer a voice, VTC, or collaboration call with audio and video capabilities enabled, or if the endpoint was compromised and remotely controlled. The stated requirements and mitigations involve muting the microphone(s) and disabling or covering the camera(s).

These or similar vulnerabilities could exist in PC based communications/collaboration applications due to an auto answer feature or compromised application or platform. As such, the simplest mitigation would be to only operate the software that accesses the microphone and camera when they are needed for communication. This does not work well for a unified communications application that is used to enhance our communications/collaboration capabilities since the application would be running most, if not all of the time when the PC is operating. In this case, the microphone could be muted and camera disabled in software as a mitigation. However, this also may not work well due to the possibility of the communications/collaboration application, microphone, or camera could be remotely activated if the platform or a communications application is compromised.  In this case positive physical controls may be required. We must also rely on our defense in depth strategy for protecting our PC applications, including our communications applications, from compromise. 

Physical disablement such as unplugging from the PC, using a physical mute switch, or covering a camera could work if using external devices. However, this mitigation would not work for embedded microphones and cameras as is the trend in laptops and monitors today. While it may not be easily feasible to physically disable an embedded microphone, the lens of an embedded camera can be covered.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure audio and video pickup/capture capabilities of microphones and cameras associated with a PC are disabled or inhibited when not required for communications such that inadvertent disclosure of aural or visual information is prevented. Ensure that operational policy and procedures are included in user training and guides.

Determine if the applicable training on the required operational procedures is provided. Inspect training materials. Interview a random sampling of users to determine if they are properly trained on this topic and actually perform the mitigating actions. Inspect a random sample of PCs that are not actively communicating to determine if the required mitigations are in place. 

NOTE: This requirement minimally involves muting the PC microphone and camera. If necessary, the camera lens must be covered, or the camera aimed at a blank wall to “mute” it. Ideally, the microphone and camera would be external devices and not embedded in the PC or an external monitor that could be disconnected from the PC when not needed. The external microphone and camera could remain connected to the PC if there was a positive physical disconnect or mute (shorting) switch for the microphone, and if the camera is disconnected by the switch or the camera lens is covered.

This is a finding if any of the inspected items are deficient such that audio and video pickup/capture capabilities of microphones and cameras associated with a PC are not disabled or inhibited when not required for communications such that inadvertent disclosure of aural or visual information is prevented.'
  desc 'fix', 'Ensure audio and video pickup/capture capabilities of microphones and cameras associated with a PC are disabled or inhibited when not required for communications such that inadvertent disclosure of aural or visual information is prevented. Ensure that operational policy and procedures are included in user training and guides.

Produce training materials and provide training such that users of PC based collaboration applications disable their microphones and cameras when not participating in a collaboration session. This minimally involves muting the PC microphone and camera. If necessary, the camera lens must be covered, or the camera aimed at a blank wall to “mute” it. Ideally, the microphone and camera would be external devices and not embedded in the PC or an external monitor that could be disconnected from the PC when not needed. The external microphone and camera could remain connected to the PC if there was a positive physical disconnect or mute (shorting) switch for the microphone, and if the camera is disconnected by the switch or the camera lens is covered.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17125r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16082'
  tag rid: 'SV-17070r1_rule'
  tag stig_id: 'VVoIP 1735 (GENERAL)'
  tag gtitle: 'Deficient Imp’n: A/V Pickup/Capture when Inactive'
  tag fix_id: 'F-16187r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Inadvertent disclosure of sensitive or classified information in aural or visual form'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
