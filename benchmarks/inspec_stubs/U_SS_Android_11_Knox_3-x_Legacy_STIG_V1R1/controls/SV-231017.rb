control 'SV-231017' do
  title 'Samsung Android must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including DoD-approved commercial app repository, management tool server, or mobile application store.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, management tool server, and/or mobile application store).

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "installs from unknown sources" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Apps >> (Overflow menu) >> Special access >> Install unknown apps.
2. Tap (Overflow menu) >> Show system apps.
3. In the "Personal" tab, ensure that each app listed has the status "Disabled" under the app name or that no apps are listed.
4. In the "Work" tab, ensure that each app listed has the status "Disabled" under the app name or that no apps are listed.

If on the management tool "installs from unknown sources" is not set to "Disallow", or on the Samsung Android device an app is listed with a status other than "Disabled", this is a finding.

NOTE: Google Play must not be disabled. Disabling Google Play will cause system instability and critical updates will not be received.'
  desc 'fix', 'Configure Samsung Android to disable unauthorized application repositories.

On the management tool, in the device restrictions section, set "installs from unknown sources" to "Disallow".

NOTE: Google Play must not be disabled. Disabling Google Play will cause system instability and critical updates will not be received.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33947r592665_chk'
  tag severity: 'medium'
  tag gid: 'V-231017'
  tag rid: 'SV-231017r608683_rule'
  tag stig_id: 'KNOX-11-001400'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-33920r592666_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
