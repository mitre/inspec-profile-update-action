control 'SV-250919' do
  title 'Apple iOS/iPadOS 15 must provide the capability for the Administrator (MDM) to perform the following management function: enable/disable VPN protection across the device and [selection: other methods].'
  desc 'The System Administrator must have the capability to configure VPN access to meet organization-specific policies based on mission needs. Otherwise, a user could inadvertently or maliciously set up a VPN and connect to a network that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Review the list of unmanaged apps installed on the iPhone and iPad and determine if any third-party VPN clients are installed. If so, verify the VPN app is not configured with a DoD network (work) VPN profile. 

This validation procedure is performed on the iOS device only.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap the "VPN and Device Management" line and determine if any "Personal VPN" exists.
4. If not, the requirement has been met.
5. If there are personal VPNs, open each VPN app. Review the list of VPN profiles configured on the VPN client.
6. Verify there are no DoD network VPN profiles configured on the VPN client.

If any third-party unmanaged VPN apps are installed (personal VPN) and they have a DoD network VPN profile configured on the client, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement.'
  desc 'fix', 'If a third-party unmanaged VPN app is installed on the iOS 15 device, do not configure the VPN app with a DoD network VPN profile.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54354r801846_chk'
  tag severity: 'low'
  tag gid: 'V-250919'
  tag rid: 'SV-250919r801848_rule'
  tag stig_id: 'AIOS-15-001000'
  tag gtitle: 'PP-MDF-321090'
  tag fix_id: 'F-54308r801847_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
