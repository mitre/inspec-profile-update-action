control 'SV-258672' do
  title 'Samsung Android must be configured to disable developer modes.'
  desc 'Developer modes expose features of the MOS that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DOD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review the configure to determine if the Samsung Android devices are disabling developer modes.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "Debugging Features" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> About phone >> Software information.
2. Tap on the Build Number to try to enable "Developer Options" and validate that action is blocked.

If on the management tool "Debugging Features" is not set to "Disallow" or on the Samsung Android device "Developer options" action is not blocked, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable developer modes.

On the management tool, in the device restrictions, set "Debugging Features" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62412r931214_chk'
  tag severity: 'medium'
  tag gid: 'V-258672'
  tag rid: 'SV-258672r931216_rule'
  tag stig_id: 'KNOX-14-210110'
  tag gtitle: 'PP-MDF-333130'
  tag fix_id: 'F-62321r931215_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
