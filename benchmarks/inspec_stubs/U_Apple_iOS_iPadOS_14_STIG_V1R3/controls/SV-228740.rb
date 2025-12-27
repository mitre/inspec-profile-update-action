control 'SV-228740' do
  title 'The mobile operating system must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review configuration settings to confirm backup in management apps is disabled and "Encrypt local backup" in iTunes (for Windows computer) and in Finder on Mac. 

Note: iTunes Backup/Finder backup is implemented by the configuration policy rule "Force encrypted backups", which is included in AIOS-14-009100, and therefore, not included in the procedure below.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify backing up app data is disabled. 

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Apps".
6. Tap a "managed app".
7. Verify "App data will not be backed up" is listed.  

Note: Steps 6 and 7 must be performed for each managed app.

If backing up app data is not disabled in the Apple iOS/iPadOS management tool or "app data will not be backed up" is not listed for each managed app on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable backup of managed apps.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30975r509848_chk'
  tag severity: 'medium'
  tag gid: 'V-228740'
  tag rid: 'SV-228740r561031_rule'
  tag stig_id: 'AIOS-14-003600'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-30952r509849_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
