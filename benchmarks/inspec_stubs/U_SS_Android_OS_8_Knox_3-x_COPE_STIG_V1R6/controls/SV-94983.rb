control 'SV-94983' do
  title 'The Samsung Android 8 with Knox whitelist must be configured to not include applications with the following characteristics: Transmit mobile device (MD) diagnostic data to non-DoD servers.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the MD, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and pre-installed applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

Core application: Any application integrated into the operating system (OS) by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has an application disable list configured to include applications with the following characteristics:

- transmit MD diagnostic data to non-DoD servers.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Application disable list" setting in the "Android Application" rule. 
2. Verify the list contains all applications that allow transmission of MD diagnostic data to non-DoD servers.

If the MDM console "Application disable list" is not properly configured or on the Samsung Android 8 with Knox device, the user is able to launch the applications on the list, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox application disable list to include applications with the following characteristics:

- transmit MD diagnostic data to non-DoD servers.

On the MDM console, add all applications that transmit MD diagnostic data to non-DoD servers to the "Application disable list" setting in the "Android Applications" rule.

Note: Refer to the Supplemental document for additional information.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80279'
  tag rid: 'SV-94983r1_rule'
  tag stig_id: 'KNOX-08-002100'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-87085r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
