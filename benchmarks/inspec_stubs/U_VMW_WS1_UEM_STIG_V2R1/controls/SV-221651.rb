control 'SV-221651' do
  title 'The MDM Agent must be configured to enable the following function: [selection: read audit logs of the MD].

This requirement is inherently met if the function is automatically implemented during MDM Agent install/device enrollment.'
  desc 'Audit logs and alerts enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify when the security posture of the device is not as expected. This enables the MDM administrator to take an appropriate remedial action.

SFR ID: FMT_SMF_EXT.4.1'
  desc 'check', 'Review the MDM Agent documentation and configuration settings to determine if the following function is enabled: read audit logs of the MD.

This validation procedure is performed on the MDM Administration Console.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> Devices & Users >> General >> Privacy and enable Request Device Log in the privacy settings.

If "Request Device Log" is present, then no device log is being requested from the MD and this is a finding.'
  desc 'fix', 'Configure the MDM Agent to enable the following function: read audit logs of the MD.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> Devices & Users >> General >> Privacy and enable Request Device Log in the privacy settings.
3. Select "SAVE".'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23366r416791_chk'
  tag severity: 'medium'
  tag gid: 'V-221651'
  tag rid: 'SV-221651r588007_rule'
  tag stig_id: 'VMW1-00-400040'
  tag gtitle: 'PP-MDM-401005'
  tag fix_id: 'F-23355r416792_fix'
  tag 'documentable'
  tag legacy: ['SV-111301', 'V-102345']
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
