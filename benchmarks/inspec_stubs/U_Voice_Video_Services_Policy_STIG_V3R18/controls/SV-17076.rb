control 'SV-17076' do
  title 'User training must include Unified Capability (UC) soft client accessory network bridging risks.'
  desc 'While a headset, microphone, webcam, combination headset/microphone, or a combination webcam/microphone can be considered to be UC soft client accessories; these are also accessories for other collaboration and communications applications. These have been discussed previously and are not included in the topic of this section. Our discussion here relates to, UC soft client specific accessories, which consist of USB phones, USB ATAs, and PPGs. A USB phone is a physical USB connected telephone instrument that associates itself with the UC soft client application running on the PC. It minimally provides a handset which includes both the mouthpiece and receiver and may provide a dial pad, a speakerphone function, or other functions. In general, these devices do not pose a security threat other than those discussed previously under audio pickup/broadcast section above. They should be operated accordingly. A USB ATA is a USB connected device that associates itself with the UC soft client application and provides the ability to utilize a standard analog telephone or speakerphone. Some USB ATAs also provide a port to which an analog phone line can be connected. This allows a single analog phone to be used with the UC soft client while also answering and placing calls via the analog phone line. This line could be connected to a local PBX or to the PSTN. Some USB phones contain a port to which an analog phone line can be connected so the USB phone can be used with it to place and receive calls. There is little risk in the operation of this kind of USB ATA or USB phone providing it operates only as described and there is no direct bridging of networks as described next. A PPG (USB connected or internal card) is a type of ATA that is a gateway intended to bridge the UC soft client application and supporting VVoIP network to an analog phone line from a local PBX or the PSTN. PPGs pose legal and fraud threats to a DoD network due to this bridging of networks. They can be used for toll fraud, toll avoidance, or placing or receiving unauthorized calls. Some USB Phones can contain a PPG. While these devices might be used to meet a specific mission requirement, their use may be illegal in certain countries and instances when connected between a DoD IP voice and data network and a public dial-up voice network. The use of any UC soft client accessory that provides a network bridging function poses both a legal and an IA threat to the DoD voice communications network. PPGs must not be used except to fulfill a validated and approved mission requirement.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 

In the event a UC soft client accessory providing a network bridging capability is approved for use to fulfill a validated and approved mission requirement, the ISSO will ensure personnel are properly trained in their implementation and proper use. This training is to be acknowledged in user agreements and included in user guides.

Determine if UC soft client accessories, including PPGs, ATAs, USB phones, or wireless headsets, that provide a network bridging capability to a different network (e.g., the PSTN or DSN) are used on a DoD PC or network. If so, further determine if there is a validated and approved mission requirement for their use. Inspect training materials on this subject. Interview a random sampling of users regarding their knowledge of the proper usage of this bridging capability. Inspect user agreements for acknowledgement of this training. 

This is a finding if the training, training materials, or user awareness of the proper use policy are deficient or if the policy is not addressed and acknowledged in signed user agreements.'
  desc 'fix', 'In the event a UC soft client accessory providing a network bridging capability is approved for use to fulfill a validated and approved mission requirement, the ISSO will ensure personnel are properly trained in their implementation and proper use. This training is to be acknowledged in user agreements and included in user guides.

Provide the appropriate user training and training materials such that users operate their UC soft client accessories, including PPGs, ATAs, USB phones, and wireless headsets that provide a network bridging in an approved manner and require they sign user agreements that acknowledge the training and policy.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17131r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16088'
  tag rid: 'SV-17076r2_rule'
  tag stig_id: 'VVoIP 1320 (GENERAL)'
  tag gtitle: 'UC soft client bridging training'
  tag fix_id: 'F-16193r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, ECSC-1, PRTN-1'
end
