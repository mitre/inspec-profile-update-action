control 'SV-31426' do
  title 'WLAN access point must be configured for Wi-Fi Alliance WPA2 security.'
  desc 'The Wi-Fi Alliance’s WPA2 certification provides assurance that the device has adequate security functionality and can implement the IEEE 802.11i standard for robust security networks.  The previous version of the Wi-Fi Alliance certification, WPA, did not require AES encryption, which must be supported for DoD WLAN implementations.  Devices without any WPA certification likely do not support required security functionality and could be vulnerable to a wide range of attacks.'
  desc 'check', 'Verify the access point is configured for either WPA2 (Enterprise) or WPA2 (Personal) authentication.  The procedure for performing this review will vary depending on the AP model.  Have the SA show the configuration setting.'
  desc 'fix', 'Configure the access point for WPA2 authentication, confidentiality, and integrity services.  In the case of WPA2 (Personal), this action will require the selection of a strong passcode or passphrase.  In the case of WPA2 (Enterprise), this action will require the organization to deploy RADIUS or equivalent authentication services on a separate server.  In cases in which the access point does not support WPA2, the organization will need to procure new equipment.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-31750r1_chk'
  tag severity: 'medium'
  tag gid: 'V-25315'
  tag rid: 'SV-31426r1_rule'
  tag stig_id: 'WIR0121'
  tag gtitle: 'WLAN Access Point WPA2 configuration'
  tag fix_id: 'F-28235r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
