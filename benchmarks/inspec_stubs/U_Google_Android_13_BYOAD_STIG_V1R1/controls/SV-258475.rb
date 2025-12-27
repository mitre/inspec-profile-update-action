control 'SV-258475' do
  title 'Google Android 13 must prohibit DOD VPN profiles in the Personal Profile.'
  desc 'If DOD VPN profiles are configured in the Personal Profile DOD sensitive data world be at risk of compromise and the DOD network could be at risk of being attacked by malware installed on the device.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Review the list of VPN profiles in the Personal Profile and determine if any VPN profiles are listed. If so, verify the VPN profiles are not configured with a DOD network VPN profile. 

This validation procedure is performed on the iOS device only.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "Network & internet".
3. Tap "VPN" and determine if any VPN profiles exist.
4. If not, the requirement has been met.
5. If there are VPN profiles, open each VPN profile.
6. Verify no DOD network VPN profiles are listed.

If any VPN profiles are installed in the Personal Profile and they have a DOD network VPN profile configured, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement.'
  desc 'fix', 'Do not configure DOD VPN profiles in the Personal Profile.'
  impact 0.3
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62215r929239_chk'
  tag severity: 'low'
  tag gid: 'V-258475'
  tag rid: 'SV-258475r929241_rule'
  tag stig_id: 'GOOG-13-701100'
  tag gtitle: 'PP-MDF-331090'
  tag fix_id: 'F-62124r929240_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
