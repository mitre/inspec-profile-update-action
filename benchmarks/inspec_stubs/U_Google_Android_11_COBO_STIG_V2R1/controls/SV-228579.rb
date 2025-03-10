control 'SV-228579' do
  title 'Google Android 11 must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, EMM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, EMM server, and/or mobile application store).

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM Console:
1. Open "Set user restrictions".
2. Verify that "Disallow install unknown sources" is toggled to On.
3. Verify that "Disallow installs from unknown sources globally" is toggled to On.

On the Google device, do the following:
1. Open Settings >> Apps and notifications >> Advanced >> Special app access.
2. Open Install unknown apps.
3. Ensure the list of apps is blank or if an app is on the list, "Disabled by admin" is listed under the app name.

If the EMM console device policy is not set to allow connections to only approved application repositories or on the Android 11 device, the device policy is not set to allow connections to only approved application repositories, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to disable unauthorized application repositories.

On the EMM Console:
1. Open "Set user restrictions".
2. Toggle "Disallow install unknown sources" to On.
3. Toggle "Disallow installs from unknown sources globally" to On.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30814r505562_chk'
  tag severity: 'medium'
  tag gid: 'V-228579'
  tag rid: 'SV-228579r852653_rule'
  tag stig_id: 'GOOG-11-000800'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-30791r505563_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
