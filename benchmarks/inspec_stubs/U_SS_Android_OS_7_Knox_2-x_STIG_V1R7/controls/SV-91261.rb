control 'SV-91261' do
  title 'The Samsung Android 7 with Knox must be configured to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled. Disable Google Crash Report.'
  desc 'Many software systems automatically send diagnostic data to the manufacturer or a third-party. This data enables the developers to understand real-world field behavior and improve the product based on that information. Unfortunately, it can also reveal information about what DoD users are doing with the systems and what causes them to fail. An adversary embedded within the software development team or elsewhere could use the information acquired to breach Samsung Android 7 with Knox security. Disabling automatic transfer of such information mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1#47a'
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the device disables automatic transfer diagnostic data to an external server other than an MDM service with which the device has enrolled.

Disabling automatic transfer of diagnostic data to an external device on Samsung Android 7 with Knox involves two steps: 
1. Disable Google Crash report.
2. Disable Report diagnostic info. 

This validation procedure covers the first of these steps. This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Google Crash Report" checkbox in the "Android Restrictions" rule. 
2. Verify the setting is not selected.

If the MDM console "Allow Google Crash Report" checkbox is selected, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled.

Configure the mobile operating system to disable Google Crash Report.

On the MDM console, deselect the "Allow Google Crash Report" checkbox in the "Android Restrictions" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76231r1_chk'
  tag severity: 'low'
  tag gid: 'V-76565'
  tag rid: 'SV-91261r1_rule'
  tag stig_id: 'KNOX-07-005700'
  tag gtitle: 'PP-MDF-301270'
  tag fix_id: 'F-83259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
