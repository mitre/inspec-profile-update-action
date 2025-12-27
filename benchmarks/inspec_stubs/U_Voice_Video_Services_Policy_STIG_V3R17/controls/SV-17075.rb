control 'SV-17075' do
  title 'Voice networks must not be bridged via a Unified Capability (UC) soft client accessory.'
  desc 'While a headset, microphone, or webcam can be considered to be UC soft client accessories, these are also accessories for other collaboration and communications applications. Our discussion here relates to, UC soft client specific accessories, which consist of USB phones, USB ATAs, and PPGs. A USB phone is a physical USB connected telephone instrument that associates itself with the UC soft client application running on the PC. It minimally provides a handset which includes both the mouthpiece and receiver and may provide a dial pad, a speakerphone function, or other functions. They should be operated accordingly. A USB ATA is a USB connected device that associates itself with the UC soft client application and provides the ability to utilize a standard analog telephone or speakerphone. Some USB ATAs also provide a port to which an analog phone line can be connected. This allows a single analog phone to be used with the UC soft client while also answering and placing calls via the analog phone line. This line could be connected to a local PBX or to the PSTN. Some USB phones contain a port to which an analog phone line can be connected so the USB phone can be used with it to place and receive calls. There is little risk in the operation of this kind of USB ATA or USB phone providing it operates only as described and there is no direct bridging of networks as described next. A PPG (USB connected or internal card) is a type of ATA that is a gateway intended to bridge the UC soft client application and supporting VVoIP network to an analog phone line from a local PBX or the PSTN. PPGs pose legal and fraud threats to a DoD network due to this bridging of networks. They can be used for toll fraud, toll avoidance, or placing or receiving unauthorized calls. Some USB Phones can contain a PPG. While these devices might be used to meet a specific mission requirement, their use may be illegal in certain countries and instances when connected between a DoD IP voice and data network and a public dial-up voice network. The use of any UC soft client accessory that provides a network bridging function poses both a legal and an IA threat to the DoD voice communications network. PPGs must not be used except to fulfill a validated and approved mission requirement. DECT 6.0 headsets provide wireless microphone and earphone use to a telephone device.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 

Ensure UC soft client accessories, including PPGs, ATAs, USB phones, and wireless headsets that provide a network bridging capability are not used on a DoD PC or network except to fulfill a validated and approved mission requirement.

Determine if UC soft client accessories, including PPGs, ATAs, USB phones, and wireless headsets, that provide a network bridging capability to the PSTN are used on a DoD PC or network. If so, further determine if there is a validated and approved mission requirement for their use. Interview a random sampling of users regarding their use of this bridging capability. This is a finding if these devices are used and there is no validated mission requirement.

Note: this requirement applies to Bluetooth, DECT/DECT 6.0, and other RF wireless technologies for accessories. Prior to procurement and implementation of any wireless accessory, a risk analysis must be performed to ensure the technology uses acceptable encryption and does not interfere with existing technology use. This guidance is not intended to replace the existing guidance available for wireless headsets used in association with mobile devices.'
  desc 'fix', 'Ensure UC soft client accessories, including PPGs, ATAs, USB phones, and wireless headsets that provide a network bridging capability are not used on a DoD PC or network except to fulfill a validated and approved mission requirement.

Discontinue the use of UC soft client accessories, including PPGs, ATAs, USB phones, and wireless headsets that provide a network bridging capability unless there is a validated and approved mission requirement for their use.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17130r4_chk'
  tag severity: 'medium'
  tag gid: 'V-16087'
  tag rid: 'SV-17075r2_rule'
  tag stig_id: 'VVoIP 1750 (GENERAL)'
  tag gtitle: 'UC soft client accessory bridging'
  tag fix_id: 'F-16192r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, DCCT-1, DCHW-1, EBCR-1, ECSC-1'
end
