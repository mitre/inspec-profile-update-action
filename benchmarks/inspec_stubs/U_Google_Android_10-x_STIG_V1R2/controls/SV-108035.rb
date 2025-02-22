control 'SV-108035' do
  title 'Google Android 10 must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, MDM server, and/or mobile application store).

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console, do the following:
1. Open Restrictions Section.
2 Toggle "Disallow installs from unknown sources globally" to on.

On the Google device, do the following:
1. Open Settings >> Apps and notifications >> Advanced >> Special app access.
2. Open Install unknown apps.
3. Ensure the list of apps is blank or if an app is on the list, "Disabled by admin" is listed under the app name.

If the MDM console device policy is not set to allow connections to only approved application repositories or on the Android 10 device, the device policy is not set to allow connections to only approved application repositories, this is a finding.'
  desc 'fix', 'Configure the Google Android device to disable unauthorized application repositories.

On the MDM Console:
1. Open Restrictions section.
2 Toggle "Disallow installs from unknown sources globally" to on.'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98931'
  tag rid: 'SV-108035r1_rule'
  tag stig_id: 'GOOG-10-000800'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-104607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
