control 'SV-257104' do
  title 'Apple iOS/iPadOS 16 must allow the administrator (MDM) to perform the following management function: enable/disable VPN protection across the device.'
  desc 'The system administrator must configure VPN access to meet organization-specific policies based on mission needs. Otherwise, a user could inadvertently or maliciously set up a VPN and connect to a network that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Review the list of unmanaged apps installed on the iPhone and iPad and determine if any third-party VPN clients are installed. If so, verify the VPN app is not configured with a DOD network (work/managed) VPN profile. 

This validation procedure is performed on the iOS device only.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap the "VPN and Device Management" line and determine if any "Personal VPN" exists.
4. If not, the requirement has been met.
5. If there are personal VPNs, open each VPN app. Review the list of VPN profiles configured on the VPN client.
6. Verify no DOD network VPN profiles are configured on the VPN client.

If any third-party unmanaged VPN apps are installed (personal VPN), and they have a DOD network VPN profile configured on the client, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement.'
  desc 'fix', 'If a third-party unmanaged VPN app is installed on the iOS 16 device, do not configure the VPN app with a DOD network VPN profile.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60789r904210_chk'
  tag severity: 'medium'
  tag gid: 'V-257104'
  tag rid: 'SV-257104r904212_rule'
  tag stig_id: 'AIOS-16-701000'
  tag gtitle: 'PP-MDF-331090'
  tag fix_id: 'F-60730r904211_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
