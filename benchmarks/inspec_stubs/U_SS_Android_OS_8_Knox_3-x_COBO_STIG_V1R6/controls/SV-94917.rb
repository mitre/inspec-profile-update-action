control 'SV-94917' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable automatic completion of browser text input.'
  desc "The auto-fill functionality in the web browser allows the user to complete a form that contains sensitive information, such as personally identifiable information (PII), without previous knowledge of the information. By allowing the use of auto-fill functionality, an adversary who learns a user's Samsung Android 8 with Knox device password, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the auto-fill feature to provide information unknown to the adversary. By disabling the auto-fill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', %q(Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing disabled automatic completion of browser text input. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Auto-Fill" check box in the "Browser Restrictions" rule. 
2. Verify the check box is not set.

On the Samsung Android 8 with Knox device, do the following:
1. Launch the browser application.
2. Select the application's setting menu.
3. Select "Auto fill profile".
4. Select "Auto fill profile" and attempt to create a profile.
5. Select "Privacy" from the setting menu.
6. Attempt to enable "Save sign-in info".

If the MDM console "Allow Auto-Fill" check box is set or on the Samsung Android 8 with Knox device, the user is able to successfully create a profile or enable "Save sign-in info", this is a finding.)
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce disabled automatic completion of browser text input. 

On the MDM console, deselect the "Allow Auto-Fill" check box in the "Browser Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80213'
  tag rid: 'SV-94917r1_rule'
  tag stig_id: 'KNOX-08-012700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
