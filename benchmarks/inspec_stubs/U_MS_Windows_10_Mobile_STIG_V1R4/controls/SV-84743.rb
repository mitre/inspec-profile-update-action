control 'SV-84743' do
  title 'Windows 10 Mobile must disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled.'
  desc 'Many software systems automatically send diagnostic data to the manufacturer or a third party. This data enables the developers to understand real world field behavior and improve the product based on that information. Unfortunately, it can also reveal information about what DoD users are doing with the systems and what causes them to fail. An adversary embedded within the software development team or elsewhere could use the information acquired to breach mobile operating system security. Disabling automatic transfer of such information mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1#45'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the device automatically sends diagnostic data to an external server other than an MDM service with which the device has enrolled.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. It assumes there is an existing device timeout policy in place that will lock the device after a certain period.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "Allow diagnostic and usage data to be sent".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. Launch "Settings".
2. Select "Privacy".
3. Select "Feedback & diagnostics".
4. Verify that the drop-down list item under Diagnostics and usage data titled "Send your device data to Microsoft" is set to "Basic" and is disabled/read-only. 

If the MDM console does not have the "Allow diagnostic and usage data to be sent" policy disabled or on the phone the "Send your device data to Microsoft" is not disabled/read-only and set to "Basic" in the specified location on the "Feedback & diagnostics" screen of the Settings app, this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "Allow diagnostic and usage data to be sent" policy to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy to managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70597r1_chk'
  tag severity: 'low'
  tag gid: 'V-70121'
  tag rid: 'SV-84743r1_rule'
  tag stig_id: 'MSWM-10-501706'
  tag gtitle: 'PP-MDF-201021'
  tag fix_id: 'F-76357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
