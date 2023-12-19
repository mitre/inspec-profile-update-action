control 'SV-241205' do
  title 'Samsung Android must be configured to disable developer modes.'
  desc 'Developer modes expose features of the MOS that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Samsung Android configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

For KPE(Legacy) COPE deployments, this configuration is the default configuration. If the management tool does not provide the capability to enable/disable "debugging features", there is NO finding because the default setting cannot be changed.

On the management tool, in the device restrictions section, verify that "Debugging Features" is set to "Disallow".

On the Samsung Android device, do the following:
1. Open "Settings".
2. Verify "Developer options" is not listed.

If on the management tool "Debugging Features" is not set to "Disallow" or on the Samsung Android device "Developer options" is listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable developer modes.

For KPE(Legacy) COPE deployments this configuration is the default configuration. No configuration required.

On the management tool, in the device restrictions section, set the "Debugging Features" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44481r680254_chk'
  tag severity: 'medium'
  tag gid: 'V-241205'
  tag rid: 'SV-241205r680256_rule'
  tag stig_id: 'KNOX-10-002700'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-44440r680255_fix'
  tag 'documentable'
  tag legacy: ['SV-109043', 'V-99939']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
