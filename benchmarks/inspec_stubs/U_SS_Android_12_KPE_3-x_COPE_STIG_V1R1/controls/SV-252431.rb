control 'SV-252431' do
  title 'Samsung Android must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including DoD-approved commercial app repository, management tool server, or mobile application store.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling unauthorized application repositories.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the Work profile restrictions, verify that "installs from unknown sources globally" is set to "Disallow".

On the Samsung Android device:
1. Open Settings >> Biometric and security >> Install unknown apps.
2. In the "Personal" tab, ensure that each app listed has the status "Disabled" under the app name or that no apps are listed.
3. In the "Work" tab, ensure that each app listed has the status "Disabled" under the app name or that no apps are listed.

If on the management tool "installs from unknown sources globally" is not set to "Disallow", or on the Samsung Android device an app is listed with a status other than "Disabled", this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable unauthorized application repositories.

On the management tool, in the Work profile restrictions, set "installs from unknown sources globally" to "Disallow".

NOTE: Google Play must not be disabled. Disabling Google Play will cause system instability and critical updates will not be received.'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55887r815504_chk'
  tag severity: 'medium'
  tag gid: 'V-252431'
  tag rid: 'SV-252431r815506_rule'
  tag stig_id: 'KNOX-12-210260'
  tag gtitle: 'PP-MDF-323050'
  tag fix_id: 'F-55837r815505_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
