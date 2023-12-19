control 'SV-250936' do
  title 'Apple iOS/iPadOS 15 allow list must be configured to not include applications with the following characteristics: voice dialing application if available when MD is locked.'
  desc 'Requiring all authorized applications to be in an application allow list prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allow list. Failure to configure an application allow list properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review configuration settings to confirm that "Allow Voice Dialing when locked" is disabled on the lock screen.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow voice dialing while device locked" is unchecked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Voice dialing while locked not allowed" is listed.

If "Allow voice dialing when locked not allowed" is checked in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "Voice dialing while locked not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Voice Control while the device is locked.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54371r801897_chk'
  tag severity: 'medium'
  tag gid: 'V-250936'
  tag rid: 'SV-250936r801899_rule'
  tag stig_id: 'AIOS-15-007300'
  tag gtitle: 'PP-MDF-323070'
  tag fix_id: 'F-54325r801898_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
