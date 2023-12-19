control 'SV-91271' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Disable Allow New Admin Install.'
  desc "An application with administrator permissions (e.g., MDM agent) is allowed to configure policies on the device. If a user is allowed to install another MDM agent on the device, then this will allow another MDM administrator (assuming it has the proper Knox licenses) the ability to configure potentially conflicting policies on the device that may not meet DoD security requirements. Although an MDM cannot disable another MDM's policies or remove another MDM from the device, there is the potential of creating policies that could conflict with enterprise policies. Therefore, other applications requesting administrator permissions should be blocked from installation.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to disallow new admin installations. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Prevent New Admin Install" checkbox in the "Android Advanced Restrictions" rule. 
2. Verify the checkbox is selected.

Note: With some MDM consoles, this policy is automatically configured when the user enrolls with the MDM.

Note: Android Device Manager must first be disabled on the device in order to successfully apply this policy. This can only be done manually on the device by selecting "Lock screen and security", then "Other security settings", then "Device administrators", and then disable Android Device Manager.

On the Samsung Android 7 with Knox device, do the following:
1. Attempt to install an application that requires admin permissions.
2. Verify the application is blocked from being installed.

If the MDM console "Prevent New Admin Install" checkbox is not selected or on the Samsung Android 7 with Knox device, the user is able to install another application requiring admin permissions on the device, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disallow new admin installations. 

On the MDM console, select the "Prevent New Admin Install" checkbox in the "Android Advanced Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76575'
  tag rid: 'SV-91271r1_rule'
  tag stig_id: 'KNOX-07-012400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
