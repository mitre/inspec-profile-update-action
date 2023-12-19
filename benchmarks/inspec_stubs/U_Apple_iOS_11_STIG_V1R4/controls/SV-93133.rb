control 'SV-93133' do
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
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77989r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78427'
  tag rid: 'SV-93133r1_rule'
  tag stig_id: 'AIOS-11-012100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
