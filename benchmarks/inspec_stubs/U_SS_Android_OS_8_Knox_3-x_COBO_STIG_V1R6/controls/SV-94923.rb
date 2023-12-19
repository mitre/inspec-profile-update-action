control 'SV-94923' do
  title 'Samsung Android 8 with Knox must be configured to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled: Disable Report Diagnostic Info.'
  desc 'Many software systems automatically send diagnostic data to the manufacturer or a third party. This data enables the developers to understand real-world field behavior and improve the product based on that information. Unfortunately, it can also reveal information about what DoD users are doing with the systems and what causes them to fail. An adversary embedded within the software development team or elsewhere could use the information acquired to breach Samsung Android 8 with Knox security. Disabling automatic transfer of such information mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1#47a'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the device disables automatic transfer of diagnostic data to an external server other than an MDM service with which the device has enrolled.

Disabling automatic transfer of diagnostic data to an external device on Samsung Android 8 with Knox involves three steps: 
1. Disable Google Crash report.
2. Disable Report diagnostic info. 
3. Disable Google Usage and diagnostics. 

This validation procedure covers the second of these steps. This validation procedure is performed on the Samsung Android 8 with Knox only.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "General management".
3. Verify the "Report diagnostic info" setting is off.

If the Samsung Android 8 with Knox device "Report diagnostic information" setting is enabled, this is a finding.

Note: This setting cannot be managed by the MDM Administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled.

Configure the mobile operating system to disable Report diagnostic information.
1. Open the device settings.
2. Select "General management".
3. Uncheck the "Report diagnostic info" setting.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79891r1_chk'
  tag severity: 'low'
  tag gid: 'V-80219'
  tag rid: 'SV-94923r1_rule'
  tag stig_id: 'KNOX-08-013300'
  tag gtitle: 'PP-MDF-301270'
  tag fix_id: 'F-87025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
