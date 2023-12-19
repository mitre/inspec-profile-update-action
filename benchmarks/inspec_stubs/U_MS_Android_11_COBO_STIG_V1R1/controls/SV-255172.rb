control 'SV-255172' do
  title 'Microsoft Android 11 must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DOD-approved commercial app repository, EMM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DOD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device has only approved application repositories (DOD-approved commercial app repository, EMM server, and/or mobile application store).

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Set user restrictions".
2. Verify that "Disallow install unknown sources" is toggled to "on".
3. Verify that "Disallow installs from unknown sources globally" is toggled to "on".

On the Microsoft Android 11 device:
1. Open Settings >> Apps and notifications >> Advanced >> Special app access.
2. Open Install unknown apps.
3. Ensure the list of apps is blank or if an app is on the list, "Disabled by admin" is listed under the app name.

If the EMM console device policy is not set to allow connections to only approved application repositories or on the Android 11 device, the device policy is not set to allow connections to only approved application repositories, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to disable unauthorized application repositories.

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disallow install unknown sources" to "on".
3. Toggle "Disallow installs from unknown sources globally" to "on".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58785r870654_chk'
  tag severity: 'medium'
  tag gid: 'V-255172'
  tag rid: 'SV-255172r870656_rule'
  tag stig_id: 'MSFT-11-000800'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-58729r870655_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
