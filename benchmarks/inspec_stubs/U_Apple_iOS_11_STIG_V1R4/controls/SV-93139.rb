control 'SV-93139' do
  title 'Apple iOS must implement the management setting: not allow a user to remove Apple iOS configuration profiles that enforce DoD security requirements.'
  desc 'Configuration profiles define security policies on Apple iOS devices. If a user is able to remove a configuration profile, the user can then change the configuration that had been enforced by that policy. Relaxing security policies may introduce vulnerabilities that the profiles had mitigated. Configuring a profile to never be removed mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review configuration settings to confirm configuration profiles are not removable.

Note: This requirement is only applicable to sites that use an authorized alternative to MDM for distribution of configuration profiles (for example, use Apple configurator) or are enrolled in Apple's Device Enrollment Program (DEP). Unless the site is enrolled in DEP, this requirement is not applicable for devices enrolled in MDM.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. The procedures below assume the site is not enrolled in DEP and are not applicable to devices under MDM management.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Security" is set to "Never".

Alternatively, verify the text "<key>PayloadRemovalDisallowed</key><true/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management". 
4. Tap each Configuration Profile from the Apple iOS management tool that contains the restrictions for the device.
5. Verify the "Delete Profile" button is not present.

If, on the Apple iOS management tool or on the iOS device, the "Delete Profile" button is available on the configuration profile, this is a finding.)
  desc 'fix', 'Configure the Apple iOS configuration profile such that it can never be removed.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77995r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78433'
  tag rid: 'SV-93139r1_rule'
  tag stig_id: 'AIOS-11-012400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
