control 'SV-228748' do
  title 'Apple iOS/iPadOS must not allow non-DoD applications to access DoD data.'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD-sensitive information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy; and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review configuration settings to confirm "Allow documents from managed apps in unmanaged apps" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow documents from managed apps in unmanaged apps" is unchecked.

Alternatively, verify the text "<key>allowOpenFromManagedToUnmanaged</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or Profiles" or "Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Opening documents from managed to unmanaged apps not allowed" is listed.

If "Allow documents from managed apps in unmanaged apps" is checked in the iOS management tool, "<key>allowOpenFromManagedToUnmanaged</key><true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Opening documents from managed to unmanaged apps not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent non-DoD applications from accessing DoD data.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30983r509872_chk'
  tag severity: 'medium'
  tag gid: 'V-228748'
  tag rid: 'SV-228748r852629_rule'
  tag stig_id: 'AIOS-14-005200'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-30960r509873_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
