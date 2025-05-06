control 'SV-96509' do
  title 'Apple iOS must not allow non-DoD applications to access DoD data.'
  desc 'Managed apps have been approved for the handling of DoD-sensitive information. Unmanaged apps are provided for productivity and morale purposes but are not approved to handle DoD-sensitive information. Examples of unmanaged apps include apps for news services, travel guides, maps, and social networking. If a document were to be viewed in a managed app and the user had the ability to open this same document in an unmanaged app, this could lead to the compromise of sensitive DoD data. In some cases, the unmanaged apps are connected to cloud backup or social networks that would permit dissemination of DoD-sensitive information to unauthorized individuals. Not allowing data to be opened within unmanaged apps mitigates the risk of compromising sensitive data.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review configuration settings to confirm "Allow documents from managed apps in unmanaged apps" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS management tool, verify "Allow documents from managed apps in unmanaged apps" is unchecked.

Alternatively, verify the text "<key>allowOpenFromManagedToUnmanaged</key><false/>" appears in the configuration profile (.mobileconfig file).

On the iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Opening documents from managed to unmanaged apps not allowed" is listed.

If "Allow documents from managed apps in unmanaged apps" is checked in the iOS management tool, "<key>allowOpenFromManagedToUnmanaged</key>
<true/>" appears in the configuration profile, or the restrictions policy on the iOS device from the iOS management tool does not list "Opening documents from managed to unmanaged apps not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent non-DoD applications from accessing DoD data.'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81795'
  tag rid: 'SV-96509r1_rule'
  tag stig_id: 'AIOS-12-005600'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-88645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000051', 'CCI-000366', 'CCI-000370']
  tag nist: ['AC-8 a', 'CM-6 b', 'CM-6 (1)']
end
