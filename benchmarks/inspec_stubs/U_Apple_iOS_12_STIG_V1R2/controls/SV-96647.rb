control 'SV-96647' do
  title 'Apple iOS must not allow unmanaged apps to read contacts from managed contacts accounts.'
  desc 'Managed apps have been approved for the handling of DoD-sensitive information. Unmanaged apps are provided for productivity and morale purposes but are not approved to handle DoD-sensitive information. Examples of unmanaged apps include apps for news services, travel guides, maps, and social networking. If a document were to be viewed in a managed app and the user had the ability to open this same document in an unmanaged app, this could lead to the compromise of sensitive DoD data. In some cases, the unmanaged apps are connected to cloud backup or social networks that would permit dissemination of DoD-sensitive information to unauthorized individuals. Not allowing data to be opened within unmanaged apps mitigates the risk of compromising sensitive data.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review configuration settings to confirm "Allow unmanaged apps to read contacts from managed contacts accounts" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS management tool, verify "Allow unmanaged apps to read contacts from managed contacts accounts" is unchecked.

On the iOS device:
1. Open the "Settings" app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Allow unmanaged apps to read contacts from managed contacts accounts" is not listed.

If "Allow unmanaged apps to read contacts from managed contacts accounts" is checked in the iOS management tool or the restrictions policy on the iOS device from the iOS management tool lists "Allow unmanaged apps to read contacts from managed contacts accounts", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent unmanaged apps to read contacts from managed contacts accounts.'
  impact 0.3
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81725r2_chk'
  tag severity: 'low'
  tag gid: 'V-81933'
  tag rid: 'SV-96647r1_rule'
  tag stig_id: 'AIOS-12-012700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-88783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000051', 'CCI-000366', 'CCI-000370']
  tag nist: ['AC-8 a', 'CM-6 b', 'CM-6 (1)']
end
