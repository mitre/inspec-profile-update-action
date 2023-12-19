control 'SV-243212' do
  title 'The WLAN access point must be configured for Wi-Fi Alliance WPA2 or WPA3 security.'
  desc "The Wi-Fi Alliance's WPA2/WPA3 certification provides assurance that the device has adequate security functionality and can implement the IEEE 802.11i standard for robust security networks. The previous version of the Wi-Fi Alliance certification, WPA, did not require AES encryption, which must be supported for DoD WLAN implementations. Devices without any WPA certification likely do not support required security functionality and could be vulnerable to a wide range of attacks."
  desc 'check', 'Verify the access point is configured for either WPA2/WPA3 (Enterprise) or WPA2/WPA3 (Personal) authentication. The procedure for performing this review will vary depending on the AP model. Have the SA show the configuration setting.

If the access point is not configured with either WPA2 or WPA3 security, this is finding.'
  desc 'fix', 'Configure the access point for WPA2 (or WPA3) authentication, confidentiality, and integrity services. 

In the case of WPA2 (Personal), this action will require the selection of a strong passcode or passphrase. 

In the case of WPA2 (Enterprise), this action will require the organization to deploy RADIUS or equivalent authentication services on a separate server.

In cases in which the access point does not support WPA2/WPA3, the organization will need to procure new equipment.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Platform'
  tag check_id: 'C-46487r720089_chk'
  tag severity: 'medium'
  tag gid: 'V-243212'
  tag rid: 'SV-243212r720091_rule'
  tag stig_id: 'WLAN-NW-000900'
  tag gtitle: 'SRG-NET-000063'
  tag fix_id: 'F-46444r720090_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
