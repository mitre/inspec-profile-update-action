control 'SV-257126' do
  title 'Apple iOS/iPadOS 16 must implement the management setting: Treat AirDrop as an unmanaged destination.'
  desc "AirDrop is a way to send contact information or photos to other users with AirDrop enabled. This feature enables a possible attack vector for adversaries to exploit. Once the attacker has gained access to the information broadcast by this feature, the attacker may distribute this sensitive information very quickly and without DOD's control or awareness. By disabling this feature, the risk of mass data exfiltration will be mitigated.

Note: If the site uses Apple's optional Automatic Device Enrollment, this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Treat AirDrop as an unmanaged destination" is enabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Treat AirDrop as unmanaged destination" is checked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Sharing managed documents using AirDrop not allowed" is listed.

If "Treat AirDrop as unmanaged destination" is disabled in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "Sharing managed documents using AirDrop not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to treat AirDrop as an unmanaged destination.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60811r904276_chk'
  tag severity: 'medium'
  tag gid: 'V-257126'
  tag rid: 'SV-257126r904278_rule'
  tag stig_id: 'AIOS-16-711500'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-60752r904277_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002008']
  tag nist: ['CM-6 b', 'IA-5 (14)']
end
