control 'SV-242511' do
  title 'Zebra Android 10 must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, MDM server, and/or mobile application store).

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open Restrictions section.
2. Toggle "Disallow installs from unknown sources globally" to On.

On the Zebra Android 10 device:
1. Open Settings >> Apps and notifications >> Advanced >> Special app access.
2. Open Install unknown apps.
3. Verify the list of apps is blank or if an app is on the list, "Disabled by admin" is listed under the app name.

If the MDM console device policy is not set to allow connections to only approved application repositories or on the Android 10 device, the device policy is not set to allow connections to only approved application repositories, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to disable unauthorized application repositories.

On the MDM console:
1. Open Restrictions section.
2. Toggle "Disallow installs from unknown sources globally" to On.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45786r714376_chk'
  tag severity: 'medium'
  tag gid: 'V-242511'
  tag rid: 'SV-242511r714378_rule'
  tag stig_id: 'ZEBR-10-000800'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-45743r714377_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
