control 'SV-219368' do
  title 'Apple iOS/iPadOS must implement the management setting: limit Ad Tracking.'
  desc %q(Ad Tracking refers to the advertisers' ability to categorize the device and spam the user with ads that are most relevant to the user's preferences. By not "Force limiting ad tracking", advertising companies are able to gather information about the user and device's browsing habits. If "Limit Ad Tracking" is not limited, a database of browsing habits of DoD devices can be gathered and stored under no supervision of the DoD. By limiting ad tracking, this setting does not completely mitigate the risk, but it limits the amount of information gathering.

SFR ID: FMT_SMF_EXT.1.1 #47)
  desc 'check', 'Review configuration settings to confirm "Force limited ad tracking" is checked.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Force limited ad tracking" is checked.

Alternatively, verify the text "<key>forceLimitAdTracking</key><true/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Restrictions".
6. Verify "Limit ad tracking enforced" is present.

If "limited ad tracking enforced" is missing in the Apple iOS/iPadOS management tool, "<key>forceLimitAdTracking</key><false/>" does not appear in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Limit ad tracking enforced", this is a finding.'
  desc 'fix', "Install a configuration profile to limit advertisers' ability to track the user's web browsing preferences."
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21093r547619_chk'
  tag severity: 'low'
  tag gid: 'V-219368'
  tag rid: 'SV-219368r604137_rule'
  tag stig_id: 'AIOS-13-010600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21092r547620_fix'
  tag 'documentable'
  tag legacy: ['SV-106569', 'V-97465']
  tag cci: ['CCI-000366', 'CCI-001199', 'CCI-000370']
  tag nist: ['CM-6 b', 'SC-28', 'CM-6 (1)']
end
