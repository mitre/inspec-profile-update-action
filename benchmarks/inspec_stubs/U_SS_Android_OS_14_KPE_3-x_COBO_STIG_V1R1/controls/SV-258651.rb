control 'SV-258651' do
  title 'Samsung Android must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including DOD-approved commercial app repository, management tool server, or mobile application store.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DOD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling unauthorized application repositories.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "installs from unknown sources globally" is set to "Disallow".

On the Samsung Android device:
1. Open Settings >> Security and privacy >> More security settings >> Install unknown apps.
2. Verify each app listed has the status "Disabled" under the app name or that no apps are listed.

If on the management tool "installs from unknown sources globally" is not set to "Disallow", or on the Samsung Android device an app is listed with a status other than "Disabled", this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable unauthorized application repositories.

On the management tool, in the device restrictions, set "installs from unknown sources globally" to "Disallow".

Note: Google Play must not be disabled. Disabling Google Play will cause system instability and critical updates will not be received.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62391r931151_chk'
  tag severity: 'medium'
  tag gid: 'V-258651'
  tag rid: 'SV-258651r931153_rule'
  tag stig_id: 'KNOX-14-110270'
  tag gtitle: 'PP-MDF-333050'
  tag fix_id: 'F-62300r931152_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
