control 'SV-254623' do
  title 'Apple iOS/iPadOS 16 must implement the management setting: Enable USB Restricted Mode.'
  desc 'The USB lightning port on an iOS device can be used to access data on the device. The required settings ensure the Apple device password is entered before a previously trusted USB accessory can connect to the device.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This is a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Allow USB Restricted Mode" is enabled.

This check procedure is performed on both the device management tool and the iPhone and iPad device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS management tool, verify "Allow USB Restricted Mode" is checked (set to "True").

On the iPhone/iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify there is no listing for "USB Accessories while locked allowed".

If "Allow USB Restricted Mode" is not enabled in the management tool and there is a restriction in listed the profile on the Apple device, this is a finding.

Note: The default configuration setting for "allow USB Restricted Mode" is "True" in most MDM products. This is the required setting. When set correctly, nothing will be listed in the Restrictions profile, and the user will be able to toggle USB accessories on/off.

Note: "Allow USB Restricted Mode" may be called "Allow USB accessories while device is locked" in some MDM consoles. The required logic is to disable USB accessory connections when the device is locked.'
  desc 'fix', 'Install a configuration profile to configure "Allow USB Restricted Mode" to "True" in the management tool. This a supervised-only control.

Note: The default configuration setting for "allow USB Restricted Mode" is "True" in most MDM products. This is the required setting. When set correctly, nothing will be listed in the Restrictions profile, and the user will be able to toggle USB accessories on/off.

Note: This control is called "Allow USB accessories while device is locked" in Apple Configurator, and the control logic is opposite to what is listed here. Ensure the MDM policy rule is set correctly (to disable USB accessory connections when the device is locked).'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58234r865839_chk'
  tag severity: 'medium'
  tag gid: 'V-254623'
  tag rid: 'SV-254623r865864_rule'
  tag stig_id: 'AIOS-16-012200'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58180r865863_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
