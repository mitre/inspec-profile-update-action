control 'SV-96477' do
  title 'If an unmanaged third-party VPN client is installed on the iOS device, it must not be configured with a DoD network (work) VPN profile.'
  desc 'Access to the DoD network must be limited for unmanaged apps because they are considered untrusted.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Review the list of unmanaged apps installed on the iOS device and determine if any third-party VPN clients are installed. If yes, verify the VPN app is not configured with a DoD network (work) VPN profile. 

This validation procedure is performed on the iOS device only.

On the iOS device, do the following:
1. Under Settings, VPN look to see if any "Personal VPN" exists.
2. If no, requirement has been met.
3. If yes, open each VPN app in turn. Review the list of VPN profiles configured on the VPN client.
4. Verify there are no DoD network VPN profiles configured on the VPN client.

If any third-party unmanaged VPN apps are installed (personal VPN) and has a DoD network VPN profile configured on the client, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'If a third-party unmanaged VPN app is installed on the iOS 12 device, do not configure the VPN app with a DoD network VPN profile.'
  impact 0.3
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81543r1_chk'
  tag severity: 'low'
  tag gid: 'V-81763'
  tag rid: 'SV-96477r1_rule'
  tag stig_id: 'AIOS-12-000800'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-88611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
