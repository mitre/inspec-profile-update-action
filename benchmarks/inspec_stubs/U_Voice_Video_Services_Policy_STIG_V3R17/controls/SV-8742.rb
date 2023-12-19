control 'SV-8742' do
  title 'VVoIP services over wireless IP networks must apply the Wireless STIG to the wireless service and endpoints.'
  desc 'The incorporation of wireless technology into the VVoIP environment elevates many existing VVoIP concerns such as quality of service (QoS), network capacity, provisioning, architecture and security. Many government entities use mobile communication solutions that include wireless VVoIP and Unified Communications (UC) applications to meet critical needs for interoperability and flexibility. Smartphone vendors integrate Wi-Fi, Bluetooth, and mobile radio that transitions seamlessly for VVoIP and UC apps. Using these capabilities over wireless technologies presents vulnerabilities to the communications carried and the VVoIP infrastructure. Confidentiality is one of the greatest concerns requiring encryption of the media and signaling. This encryption is in addition to the WLAN encryption required by the Wireless STIG and the endpoints must authenticate to the WLAN before being granted access. Another great concern for using wireless VVoIP communications services is reliability and availability when using the technology for critical C2 communications. Initiated calls could be blocked at either the transmitting end or the receiving end. This could be because the spectrum or channels could be busy/overloaded, unavailable, or deliberately jammed by an adversary. As such, VVoIP services should not be relied upon for C2 communications.'
  desc 'check', 'Inspect the VVoIP site documentation to confirm VVoIP services over wireless IP networks apply the Wireless STIG to the wireless services and endpoints, specifically services used over a Wireless LAN (WLAN - Wi-Fi 802.11x) or Wireless MAN (WMAN - WiMAX 802.16) connection. Ensure the applicable endpoint and service related requirements contained in the Wireless STIG have been applied to the wireless VVoIP service and endpoints in addition to the applicable VVoIP STIG requirements.

Determine if the site has implemented or supports IP based wireless (802.11x or 802.16) VVoIP endpoints. If so this implies that there is a supporting WLAN and any applicable requirements in the Wireless STIG apply to the wireless VVoIP endpoints and service in addition to those in this checklist. 

Obtain a copy of the Wireless SRR or Self-Assessment results and review for compliance. If SRR results are not available, then perform a wireless SRR on a representative number of wireless VVoIP endpoints and on the service. 

Areas of primary concern are, but are not limited to the following: 
- Is the endpoint an approved endpoint?
- Is the endpoint configured to support the required VVoIP endpoint, registration, authentication, and media/signaling encryption requirements? 
- Is the endpoint configured to support the required WLAN access control, authentication, and encryption requirements?

If it is evident the appropriate STIGs have not been applied, this is a finding. 

NOTE: Wireless endpoints in this case are typically going to be handheld devices such as a dedicated VVoIP only "cordless phone", a cellular phone with dual cellular and Wi-Fi (possibly including WiMAX) capabilities, or a PDA/PED with a UC soft client installed. However, the endpoints could also be desk phones and some could also support Bluetooth headsets, which are also covered in the Wireless STIG.'
  desc 'fix', 'Apply requirements contained the Wireless STIG wherever VVoIP over wireless LAN (Wi-Fi 802.11x) or Wireless MAN (WiMAX 802.16) is used. Ensure the applicable endpoint and service related requirements contained in the Wireless STIG have been applied to the wireless VVoIP service and endpoints in addition to the applicable VVoIP STIG requirements.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23624r2_chk'
  tag severity: 'low'
  tag gid: 'V-8256'
  tag rid: 'SV-8742r2_rule'
  tag stig_id: 'VVoIP 1035 (GENERAL)'
  tag gtitle: 'Enforce Wireless STIG'
  tag fix_id: 'F-20139r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, ECWN-1'
end
