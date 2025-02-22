control 'SV-91219' do
  title 'The Samsung Android 7 with Knox must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store]. Disable Google Play.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Note, this requirement is Not Applicable if the AO has approved an unmanaged personal container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Configuring an application installation policy on Samsung Android 7 with Knox by specifying an application repository involves two steps: (1) Disabling Google Play, (2) Disabling unknown application sources. This validation procedure covers the first of these steps.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, MDM server, and/or mobile application store). 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Disable Android Market" setting in the "Android Applications" rule. 
2. Verify it is "Enabled".

On the Samsung Android 7 with Knox device, do the following:
1. Attempt to locate the "Google Play" application.
2. Verify it is not present on the device. 

If the MDM console "Disable Android Market" is not "Enabled" or on the Samsung Android 7 with Knox device, the user can successfully launch Google Play, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable unauthorized application repositories.

On the MDM console, enable "Disable Android Market" in the "Android Applications" rule. 

Note: Some MDM consoles may refer to "Google Play" instead of "Android Market".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76523'
  tag rid: 'SV-91219r1_rule'
  tag stig_id: 'KNOX-07-001100'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-83205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
