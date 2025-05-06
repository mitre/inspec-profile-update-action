control 'SV-251813' do
  title 'Samsung Android must be configured to disable developer modes.'
  desc 'Developer modes expose features of the MOS that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review the configure to determine if the Samsung Android devices are disabling developer modes.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "Debugging Features" is set to "Disallow".

On the Samsung Android device: 
1. Open "Settings".
2. Verify "Developer options" is not listed.

If on the management tool "Debugging Features" is not set to "Disallow" or on the Samsung Android device "Developer options" is listed, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable developer modes.

On the management tool, in the device restrictions, set "Debugging Features" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55273r814193_chk'
  tag severity: 'medium'
  tag gid: 'V-251813'
  tag rid: 'SV-251813r814195_rule'
  tag stig_id: 'KNOX-12-110110'
  tag gtitle: 'PP-MDF-323130'
  tag fix_id: 'F-55227r814194_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
