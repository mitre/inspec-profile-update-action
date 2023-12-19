control 'SV-254770' do
  title 'Google Android 13 must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DOD-approved commercial app repository, MDM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DOD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the mobile device has only approved application repositories (DOD-approved commercial app repository, EMM server, and/or mobile application store).

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device. 

On the EMM Console:

COBO and COPE:

1. Open "Set user restrictions".
2. Verify that "Disallow install unknown sources" is toggled to "ON".
3. Verify that "Disallow installs from unknown sources globally" is toggled to "ON".

On the Google Android 13 device:

COBO and COPE:

1. Open Settings >> Apps >> Special app access.
2. Open Install unknown apps.
3. Ensure the list of apps is blank or if an app is on the list, "Disabled by admin" is listed under the app name.

If the EMM console device policy is not set to allow connections to only approved application repositories or on the managed Google Android 13 device, the device policy is not set to allow connections to only approved application repositories, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable unauthorized application repositories.

On the EMM Console:

COBO and COPE:

1. Open "Set user restrictions".
2. Toggle "Disallow install unknown sources" to "ON".
3. Toggle "Disallow installs from unknown sources globally" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58381r862690_chk'
  tag severity: 'medium'
  tag gid: 'V-254770'
  tag rid: 'SV-254770r862692_rule'
  tag stig_id: 'GOOG-13-006500'
  tag gtitle: 'PP-MDF-323050'
  tag fix_id: 'F-58327r862691_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
