control 'SV-257134' do
  title 'Apple iOS/iPadOS 16 must not allow DOD applications to access non-DOD data.'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to sensitive DOD information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy; therefore, the administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review configuration settings to confirm "Allow documents from unmanaged apps in managed apps" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow documents from unmanaged apps in managed apps" is unchecked.

On the iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Opening documents from unmanaged to managed apps not allowed" is listed.

If "Allow documents from unmanaged apps in managed apps" is checked in the iOS management tool or the restrictions policy on the iPhone and iPad does not list "Opening documents from unmanaged to managed apps not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent DOD applications from accessing non-DOD data.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60819r904300_chk'
  tag severity: 'medium'
  tag gid: 'V-257134'
  tag rid: 'SV-257134r904302_rule'
  tag stig_id: 'AIOS-16-714900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-60760r904301_fix'
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002530']
  tag nist: ['AC-6 (8)', 'SC-39']
end
