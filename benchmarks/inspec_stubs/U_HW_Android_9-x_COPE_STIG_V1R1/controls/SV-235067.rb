control 'SV-235067' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device has only approved application repositories (DoD-approved commercial app repository, MDM server, and/or mobile application store).

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open Restrictions section.
2. Set Allow "Honeywell Play" (Uses only Managed Honeywell Play).
3. Ensure that Disallow is set for "Install unknown sources".

On the Honeywell Android Pie device:
1. Open Settings >> Apps and notifications >> Advanced >> Special app access.
2. Open Install unknown apps.
3. Ensure the list of apps is blank or if an app is on the list, "Disabled by admin" is listed under the app name.

If the MDM console device policy is not set to allow connections to only approved application repositories or on the Honeywell Android Pie device, the device policy is not set to allow connections to only approved application repositories, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to disable unauthorized application repositories.

On the MDM console:
1. Open Restrictions section.
2. Set Allow "Honeywell Play" (Uses only Managed Honeywell Play).
3. Set Disallow "Install unknown sources".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38286r623216_chk'
  tag severity: 'medium'
  tag gid: 'V-235067'
  tag rid: 'SV-235067r626527_rule'
  tag stig_id: 'HONW-09-000800'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-38249r623217_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
