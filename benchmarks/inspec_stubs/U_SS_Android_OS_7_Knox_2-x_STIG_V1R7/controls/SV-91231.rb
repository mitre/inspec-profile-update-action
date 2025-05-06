control 'SV-91231' do
  title 'The Samsung Android 7 with Knox whitelist must be configured to not include applications with the following characteristics: - Voice dialing application if available when MD is locked.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. Core application – any application integrated into the operating system (OS) by the OS or mobile device (MD) vendors. Pre-installed application – additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'This requirement is Not Applicable if the AO has approved unmanaged personal space/container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has an application disable list configured to include applications with the following characteristics:

- Voice dialing application if available when MD is locked.

This validation procedure is performed only on the MDM Administration Console.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Application disable list" setting in the "Android Application" rule. 
2. Verify the list contains all applications which allow voice dialing when MD is locked.

If the MDM console "Application disable list" is not properly configured or on the Samsung Android 7 with Knox device, the user is able to launch the applications on the list, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox application disable list to include applications with the following characteristics:

- Voice dialing application if available when MD is locked.

On the MDM console, add all applications which provide voice dialing when MD is locked to the "Application disable list" setting in the "Android Applications" rule. 

Note: Refer to the Supplemental document for additional information.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76535'
  tag rid: 'SV-91231r1_rule'
  tag stig_id: 'KNOX-07-001900'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-83217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
