control 'SV-91221' do
  title 'The Samsung Android 7 with Knox must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store]. Disable unknown sources.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Configuring an application installation policy on Samsung Android 7 with Knox by specifying an application repository involves two steps: (1) Disabling Google Play, (2) Disabling unknown application sources. This validation procedure covers the second of these steps.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, MDM server, and/or mobile application store). 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Install Non Market App" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Attempt to enable "Unknown sources".
4. Verify it cannot be enabled. 

If the MDM console "Allow Install Non Market App" checkbox is selected or on the Samsung Android 7 with Knox device, the user can successfully enable "Unknown sources", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable unauthorized application repositories.

On the MDM console, deselect the "Allow Install Non Market App" checkbox in the "Android Restrictions" rule.

Note: Some MDM consoles may refer to "Unknown Sources" instead of "Non Market App".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76525'
  tag rid: 'SV-91221r1_rule'
  tag stig_id: 'KNOX-07-001200'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-83207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
