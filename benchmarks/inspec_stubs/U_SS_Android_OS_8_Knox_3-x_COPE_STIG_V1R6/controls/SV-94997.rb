control 'SV-94997' do
  title 'Samsung Android 8 with Knox must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store]: Disable unknown sources.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, MDM server, and/or mobile application store). 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Install Non Market App" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Apps".
3. Select "Special access" in the overflow menu.
4. Select "Install unknown apps".
5. Attempt to enable "Allow from this source" for any application.
6. Verify it cannot be enabled.

If the MDM console "Allow Install Non Market App" check box is selected or on the Samsung Android 8 with Knox device, the user can successfully enable "Allow from this source" for an application, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable unauthorized application repositories.

On the MDM console, deselect the "Allow Install Non Market App" check box in the "Android Restrictions" rule.

Note: Some MDM consoles may refer to "Unknown Sources" instead of "Non Market App".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80293'
  tag rid: 'SV-94997r1_rule'
  tag stig_id: 'KNOX-08-002900'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-87099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
