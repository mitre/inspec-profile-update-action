control 'SV-230985' do
  title 'Samsung Android must be configured to disable developer modes.'
  desc 'Developer modes expose features of the MOS that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Samsung Android configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "Debugging Features" is set to "Disallow".

On the Samsung Android device: 
1. Open "Settings".
2. Verify "Developer options" is not listed.

If on the management tool "Debugging Features" is not set to "Disallow" or on the Samsung Android device "Developer options" is listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable developer modes.

On the management tool, in the device restrictions section, set the "Debugging Features" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33915r592447_chk'
  tag severity: 'medium'
  tag gid: 'V-230985'
  tag rid: 'SV-230985r607691_rule'
  tag stig_id: 'KNOX-11-005100'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-33888r592448_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
