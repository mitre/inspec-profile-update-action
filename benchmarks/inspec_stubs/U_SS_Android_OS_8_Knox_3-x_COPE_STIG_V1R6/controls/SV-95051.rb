control 'SV-95051' do
  title 'Samsung Android 8 with Knox must be configured to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled: Disable Google Crash Report.'
  desc 'Many software systems automatically send diagnostic data to the manufacturer or a third party. This data enables the developers to understand real-world field behavior and improve the product based on that information. Unfortunately, it can also reveal information about what DoD users are doing with the systems and what causes them to fail. An adversary embedded within the software development team or elsewhere could use the information acquired to breach Samsung Android 8 with Knox security. Disabling automatic transfer of such information mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1#47a'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the device disables automatic transfer of diagnostic data to an external server other than an MDM service with which the device has enrolled.

Disabling automatic transfer of diagnostic data to an external device on Samsung Android 8 with Knox involves three steps: 
1. Disable Google Crash report.
2. Disable Report diagnostic information. 
3. Disable Google Usage and diagnostics. 

This validation procedure covers the first of these steps. This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Google Crash Report" check box in the "Android Restrictions" rule. 
2. Verify the setting is not selected.

If the MDM console "Allow Google Crash Report" check box is selected, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled.

Configure the mobile operating system to disable Google Crash Report.

On the MDM console, deselect the "Allow Google Crash Report" check box in the "Android Restrictions" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80019r1_chk'
  tag severity: 'low'
  tag gid: 'V-80347'
  tag rid: 'SV-95051r1_rule'
  tag stig_id: 'KNOX-08-013200'
  tag gtitle: 'PP-MDF-301270'
  tag fix_id: 'F-87153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
