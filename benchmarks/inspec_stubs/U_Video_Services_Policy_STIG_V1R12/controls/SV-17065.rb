control 'SV-17065' do
  title 'Deficient SOP or enforcement regarding presentation and application sharing via a PC or VTC.'
  desc 'Visual collaboration often requires the sharing or display of presentations, open documents, and white board information to one or more communicating endpoints. While the technology for doing this is different between hardware based VTC endpoints and PC based application endpoints, the vulnerability is the same. In both cases, the displayed information typically resides on a PC. While in presentation/sharing mode, care must be exercised so that the PC user does not inadvertently display and transmit information on their workstation which is not part of the communications session and not intended to be viewed by the other communicating parties. Users must be aware that anything they display on their PC monitor while presenting to a communications session may be displayed on the other communicating endpoints. This is particularly true when the PC video output is connected to a VTC CODEC since the information will be displayed on all of the conference monitors. This presentation/sharing feature could result in the disclosure of sensitive or classified information to individuals that do not have a validated need-to-know or have the proper clearance to view the information. Thus the presentation/sharing feature presents a vulnerability to other information displayed on the PC if the feature is misused. This is a problem when sharing (displaying) a PC desktop via any collaboration tool using any connection method. There is little that can be done to mitigate this vulnerability other than to develop policy and procedures to present to collaborative communications sessions. All users which perform this function must have awareness of the issues and be trained in the proper operational procedures. Such procedures may require that there be no non-session related documents or windows open or minimized on the PC while presenting or sharing. An additional requirement may be that the user may not permit others in a session to remotely control their PC. A SOP is needed that addresses mitigations for the vulnerabilities posed by PC data and presentation sharing. Such an SOP could include the following discussion. If a user needs to view non meeting related information while presenting to a conference, the PC external display port must be turned off or better yet, the cable disconnected. Dual monitor operation of the PC could mitigate this problem somewhat. The second monitor output would be connected to the CODEC which would serve as the second monitor. Using this method, any information may be viewed on the native PC monitor while the presentation can be displayed on the VTU presentation screen.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure a policy and procedure is in place and enforced that addresses the proper implementation and use of the “Presentation and Sharing” features of collaboration applications and devices. This policy and SOP will be based on the specific application’s or device’s capabilities and will address mitigations for the possible inadvertent disclosure of information to conferees that have no need to see or have access to such information. Operational policy and procedures must be included in user training and guides.

Interview the IAO and inspect the applicable SOP. The SOP should address the proper implementation and use of the “Presentation and Sharing” features of collaboration applications and devices. This policy and SOP will be based on the specific application’s or device’s capabilities and will address mitigations for the possible inadvertent disclosure of information to conferees that have no need to see or have access to.

Inspect user training materials and discuss practices to determine if information regarding the SOP is conveyed. Interview a random sampling of users to confirm their awareness of the SOP and related information.
This is a finding if the if the SOP or training is deficient.'
  desc 'fix', 'Ensure a policy and procedure is in place and enforced that addresses the proper implementation and use of the “Presentation and Sharing” features of collaboration applications and devices. This policy and SOP will be based on the specific application’s or device’s capabilities and will address mitigations for the possible inadvertent disclosure of information to conferees that have no need to see or have access to such information. Operational policy and procedures must be included in user training and guides.

Produce an SOP that addresses the proper implementation and use of the “Presentation and Sharing” features of collaboration applications and devices. This policy and SOP will be based on the specific application’s or device’s capabilities and will address mitigations for the possible inadvertent disclosure of information to conferees that have no need to see or have access to. Operational policy and procedures must be included in user training and guides.

Provide appropriate training such that users follow the SOP. Enforce user compliance with the SOP'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16078'
  tag rid: 'SV-17065r1_rule'
  tag stig_id: 'VVoIP/VTC 1915 (GENERAL)'
  tag gtitle: 'Deficient SOP; Presentation/App Sharing'
  tag fix_id: 'F-16183r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent and/or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Other', 'Information Assurance Manager', 'Information Assurance Officer']
end
