control 'SV-17073' do
  title 'Unified Capability (UC) soft client accessories must be tested and approved.'
  desc 'While a headset, microphone, or webcam can be considered to be UC soft client accessories, these are also accessories for other collaboration and communications applications. Our discussion here relates to, UC soft client specific accessories, which include USB phones, USB ATAs, PPGs, and headsets. A USB phone is a physical USB connected telephone instrument that associates itself with the UC soft client application running on the PC. It minimally provides a handset which includes both the mouthpiece and receiver and may provide a dial pad, a speakerphone function, or other functions. A USB ATA is a USB connected device that associates itself with the UC soft client application and provides the ability to utilize a standard analog telephone or speakerphone. Some USB ATAs also provide a port to which an analog phone line can be connected. This allows a single analog phone to be used with the UC soft client while also answering and placing calls via the analog phone line. This line could be connected to a local PBX or to the PSTN. Some USB phones contain a port to which an analog phone line can be connected so the USB phone can be used with it to place and receive calls. There is little risk in the operation of this kind of USB ATA or USB phone providing it operates only as described and there is no direct bridging of networks as described next. A PPG (USB connected or internal card) is a type of ATA that is a gateway intended to bridge the UC soft client application and supporting VVoIP network to an analog phone line from a local PBX or the PSTN. PPGs pose legal and fraud threats to a DoD network due to this bridging of networks. PPGs can be used for toll fraud, toll avoidance, or placing or receiving unauthorized calls. Some USB Phones contain a PPG. While these devices might be used to meet a specific mission requirement, their use may be illegal in certain countries and instances when connected between a DoD IP voice and data network and a public dial-up voice network. The use of any UC soft client accessory that provides a network bridging function poses both a legal and an IA threat to the DoD voice communications network. PPGs must not be used except to fulfill a validated and approved mission requirement. DECT 6.0 headsets provide wireless microphone and earphone use to a telephone device.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 

Ensure UC soft client accessories, including PPGs, ATAs, USB phones, and wireless headsets capabilities are reviewed and their functionality tested or validated prior to approval, providing them to users, or implementing them.

Determine if the use of USB phones, USB ATAs, PPGs, or wireless headsets is permitted and if they are provided to users. If so, determine if the devices have been reviewed and tested as necessary with regard to their network bridging capabilities. If these devices are provided to users and they have not been properly reviewed or tested, this is a finding. 

Note: this requirement applies to Bluetooth, DECT/DECT 6.0, and other RF wireless technologies for accessories. Prior to procurement and implementation of any wireless accessory, a risk analysis must be performed to ensure the technology uses acceptable encryption and does not interfere with existing technology use. This guidance is not intended to replace the existing guidance available for wireless headsets used in association with mobile devices.'
  desc 'fix', 'Ensure UC soft client accessories (i.e., PPGs, ATAs, and/or USB phones) capabilities are reviewed and their functionality tested or validated prior to approval, providing them to users, or implementing them.

Review and test the use of USB phones, USB ATAs, PPGs, and wireless headsets for network bridging capabilities. Do not use such devices if the capability exists except to fulfill a validated mission requirement.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17128r2_chk'
  tag severity: 'low'
  tag gid: 'V-16085'
  tag rid: 'SV-17073r2_rule'
  tag stig_id: 'VVoIP 1745 (GENERAL)'
  tag gtitle: 'UC soft client accessory approval'
  tag fix_id: 'F-16190r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, DCCT-1, DCHW-1, EBCR-1, ECSC-1'
end
