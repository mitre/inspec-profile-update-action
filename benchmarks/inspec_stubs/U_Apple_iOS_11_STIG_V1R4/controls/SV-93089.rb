control 'SV-93089' do
  title 'Apple iOS must not allow backup of managed app data to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review configuration settings to confirm backup in management apps is disabled and iTunes Backup is encrypted. 

Note: iTunes Backup is implemented by the configuration policy rule "Force encrypted backups", which is included in AIOS-11-011100, and therefore, not included in the procedure below.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify backing up app data is disabled. 

Note: If an organization has multiple configuration profiles, the procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Apps".
6. Tap managed app.
7. Verify "App data will not be backed up" is listed.
Note: Steps 6 and 7 must be performed for each managed app.

If backing up app data is not disabled in the Apple iOS management tool or "app data will not be backed up" is not listed for each managed app on the Apple iOS device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable backup of managed apps.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78383'
  tag rid: 'SV-93089r1_rule'
  tag stig_id: 'AIOS-11-003900'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-85115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
