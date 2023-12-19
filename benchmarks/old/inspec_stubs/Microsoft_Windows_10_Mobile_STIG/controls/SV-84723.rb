control 'SV-84723' do
  title 'Windows 10 Mobile must enable VPN protection.'
  desc 'A key characteristic of a mobile device is that they typically will communicate wirelessly and are often expected to reside in locations outside the physical security perimeter of a DoD facility. In these circumstances, the threat of eavesdropping is substantial. Virtual private networks (VPNs) provide confidentiality and integrity protection for data transmitted over untrusted media (e.g., air) and networks (e.g., the Internet). They also provide authentication services to ensure that only authorized users are able to use them. Consequently, enabling VPN protection counters threats to communications to and from mobile devices.

SFR ID: FMT_SMF_EXT.1.1 #03'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the device has enabled VPN protection.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. 

On the MDM administration console:

Ask the MDM administrator to verify that a site-specific VPN policy has been configured on the MDM and deployed to managed Windows 10 Mobile devices.

On the Windows 10 Mobile device:

1. Navigate to "Settings"/"Network & Wireless"/"VPN".
2. Verify that on the VPN settings page that there is a site-specific VPN profile listed under the "+ Add a VPN connection" button.

If the MDM is not configured to enforce a VPN profile for connectivity or if the DoD VPN profile is not shown on the "VPN" screen of the Settings app on the Windows 10 Mobile device, this is a finding.'
  desc 'fix', 'Configure the MDM system to create a site-specific VPN profile that is configured to route traffic through DoD authorized networks.

Deploy the MDM policy on managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70577r1_chk'
  tag severity: 'low'
  tag gid: 'V-70101'
  tag rid: 'SV-84723r1_rule'
  tag stig_id: 'MSWM-10-202409'
  tag gtitle: 'PP-MDF-201025'
  tag fix_id: 'F-76337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
