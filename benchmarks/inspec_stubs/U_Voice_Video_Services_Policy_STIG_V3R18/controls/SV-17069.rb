control 'SV-17069' do
  title 'Deficient training for the secure operation of PC desktop, presentation, or application sharing capabilities of a collaboration tool.'
  desc 'Visual collaboration often requires the sharing or display of presentations, open documents, and white board information to one or more communicating endpoints. While the technology for doing this is different between hardware based endpoints, and PC based application endpoints, the vulnerability is the same. In both cases, the displayed information typically resides on a PC. While in presentation/sharing mode, care must be exercised so that the PC user does not inadvertently display and transmit information on their workstation that is not part of the communications session and not intended to be viewed by the other communicating parties. Users must be aware that anything they display on their PC monitor while presenting to a communications session may be displayed on the other communicating endpoints. This is particularly true when the PC video output is connected to a VTC CODEC since the information is displayed on all of the conference monitors. This presentation/sharing feature could result in the disclosure of sensitive or classified information to individuals that do not have a validated need-to-know or have the proper clearance to view the information. Thus the presentation/sharing feature presents a vulnerability to other information displayed on the PC if the feature is misused. This is a problem when sharing (displaying) a PC desktop via any collaboration tool using any connection method. The mitigation for this vulnerability is to develop policy and procedures on how to securely present to collaborative communications sessions . All users that perform this function must have awareness of the issues and be trained in the proper operational procedures. Such procedures may require that there be no non-session related documents or windows open or minimized on the PC while presenting or sharing. An additional requirement may be that the user may not permit others in a session to remotely control their PC. A similar issue is that some PC based collaboration applications can permit a user to allow other session participants to remotely control their PC. Depending upon how this feature is implemented and limited, it could lead to undesired activities on the part of the person in control and possible compromise of information that is external to the collaboration session. This would be the case if such sharing or remote control provided access to the local hard drive and non session related applications or network drives accessible from the controlled PC.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure users of PC based collaboration applications are trained to only share control of their PC or applications with other users that they are familiar with and/or can identify as trustworthy.  

Determine if training is provided such that users of PC based collaboration applications only share control of their PC or applications with other users with whom they are familiar with and/or can identify as trustworthy. Inspect training materials for related content. Interview a random sampling of users to determine if they are properly trained on this topic. 

This is a finding if the training or training materials are deficient.'
  desc 'fix', 'Ensure users of PC based collaboration applications are trained to only share control of their PC or applications with other users that they are familiar with and/or can identify as trustworthy.  

Produce training materials and provide training such that users of PC based collaboration applications only share control of their PC or applications with other users with whom they are familiar with and/or can identify as trustworthy.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17124r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16081'
  tag rid: 'SV-17069r1_rule'
  tag stig_id: 'VVoIP 1310 (GENERAL)'
  tag gtitle: 'Deficient User Trng: PC Collab App Shar’g Security'
  tag fix_id: 'F-16186r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
