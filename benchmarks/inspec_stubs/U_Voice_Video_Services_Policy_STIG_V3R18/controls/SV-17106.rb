control 'SV-17106' do
  title 'Deficient user training regarding the use of non-approved applications and hardware.'
  desc 'The second mitigation for the vulnerability regarding personally installed apps and hardware is the administrative prevention of the installation of the applications in question by the PC user. This is generally handled by today’s policies and STIG requirements that are used to secure DoD workstations which limit the privileges of the workstation user. Users that are not given administrator rights on their workstations cannot install such applications. On the other hand, some users are given these rights. To cover those workstations on which the user can install software, the above policy must be enforced, and must be augmented by user awareness, training, and user agreements. The limitations of these IA controls are extensible to hardware devices that provide the same or similar functionality. Such a device is a stick phone, because it contains a client application. Such devices are available for commercial VoIP services such as Vonage and Skype. Another device that can be included under these guidelines is a PPG that connects a soft-phone to a traditional phone line permitting the uncontrolled bridging of voice networks.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure: 
- Users are made aware and trained that even if their permissions allow, they are not to download and install IM and/or soft-phone applications on their DoD PCs that use or connect to public IM and/or IP telephony services unless directed to do so by their DoD organization for the fulfillment of an official requirement. 
- Users are made aware and trained that, they are not to attempt to use a stick phone on their DoD PC that associates itself or connects to a public IM or IP telephony services unless directed to do so by their DoD organization for the fulfillment of an official requirement. 
- Users are made aware and trained that, they are not to attempt to use a PPG on their DoD PC that associates itself with an installed soft-phone unless directed to do so by their DoD organization for the fulfillment of an official requirement. 
- The limitations in this requirement are listed in a signed user agreement.

Note: DAA approval and possibly DISN DAA approval is required in the event IM and/or soft-phone applications, or stick phones that associate with or connect to a public IM or IP telephony service are to be implemented by a DoD component.

Ask the IAO if the required user training is provided and if the items in the requirement are listed in a signed user agreement.

Inspect user agreements for inclusion of the limitations and user acknowledgment.

Additionally, interview a random sample of users to determine their awareness of these limitations. 

This is a finding if training is inadequate and users are unaware of the limitations and/or the limitations are not listed in signed user agreements.'
  desc 'fix', 'Ensure users are trained as follows: 
- Users are made aware and trained that even if their permissions allow, they are not to download and install IM and/or soft-phone applications on their DoD PCs that use or connect to public IM and/or IP telephony services unless directed to do so by their DoD organization for the fulfillment of an official requirement. 
- Users are made aware and trained that, they are not to attempt to use a stick phone on their DoD PC that associates itself or connects to a public IM or IP telephony services unless directed to do so by their DoD organization for the fulfillment of an official requirement. 
- Users are made aware and trained that, they are not to attempt to use a PPG on their DoD PC that associates itself with an installed soft-phone unless directed to do so by their DoD organization for the fulfillment of an official requirement.

Additionally ensure: 
- The limitations in this requirement are listed in a signed user agreement.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17162r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16118'
  tag rid: 'SV-17106r1_rule'
  tag stig_id: 'VVoIP 1325 (GENERAL)'
  tag gtitle: 'Deficient User Trng: Non Apprvd PC Comm App/Hdwr'
  tag fix_id: 'F-16224r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Compromise of the supporting PC, attached network, and/or network resources'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
