control 'SV-96543' do
  title 'Apple iOS must implement the management setting: Treat Airdrop as an unmanaged destination.'
  desc "An Airdrop feature is a way to send contact information or photos to other users with this same feature enabled. This feature enables a possible attack vector for adversaries to exploit. Once the attacker has gained access to the information broadcast by this feature, he/she may distribute this sensitive information very quickly and without DoD's control or awareness. By disabling this feature, the risk of mass data exfiltration will be mitigated.

Note: If the site uses Apple's optional Device Enrollment Program (DEP), this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Treat AirDrop as an unmanaged destination" is enabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Treat Airdrop as unmanaged destination" is checked.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Sharing managed documents using AirDrop not allowed" is listed.

If "Treat Airdrop as unmanaged destination" is disabled in the Apple iOS management tool or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Sharing managed documents using AirDrop not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to treat AirDrop as an unmanaged destination.'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81621r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81829'
  tag rid: 'SV-96543r1_rule'
  tag stig_id: 'AIOS-12-011700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-88679r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002008']
  tag nist: ['CM-6 b', 'IA-5 (14)']
end
