control 'SV-228733' do
  title 'The mobile operating system must provide the capability for the Administrator (MDM) to perform the following management function: enable/disable VPN protection across the device and [selection: other methods].'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD-sensitive Information.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Review the list of unmanaged apps installed on the iPhone and iPad and determine if any third-party VPN clients are installed. If yes, verify the VPN app is not configured with a DoD network (work) VPN profile. 

This validation procedure is performed on the iOS device only.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. In the "VPN" line, look to see if any "Personal VPN" exists.
4. If not, the requirement has been met.
5. If so, open each VPN app. Review the list of VPN profiles configured on the VPN client.
6. Verify there are no DoD network VPN profiles configured on the VPN client.

If any third-party unmanaged VPN apps are installed (personal VPN) and have a DoD network VPN profile configured on the client, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement.'
  desc 'fix', 'If a third-party unmanaged VPN app is installed on the iOS 14 device, do not configure the VPN app with a DoD network VPN profile.'
  impact 0.3
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30968r509827_chk'
  tag severity: 'low'
  tag gid: 'V-228733'
  tag rid: 'SV-228733r561031_rule'
  tag stig_id: 'AIOS-14-000500'
  tag gtitle: 'PP-MDF-302060'
  tag fix_id: 'F-30945r509828_fix'
  tag 'documentable'
  tag cci: ['CCI-000066', 'CCI-000366', 'CCI-000370']
  tag nist: ['AC-17 e', 'CM-6 b', 'CM-6 (1)']
end
