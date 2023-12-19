control 'SV-103047' do
  title 'The Samsung Android whitelist must be configured to not include applications with the following characteristics: - back up mobile device data to non-DoD cloud servers (including user and application access to cloud backup services); - transmit mobile device diagnostic data to non-DoD servers; - voice assistant application if available when the mobile device is locked; - voice dialing application if available when the mobile device is locked; - allows synchronization of data or applications between devices associated with the user; and - allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other mobile devices or printers.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment. 

Application note: The application whitelist, in addition to controlling the installation of applications on the mobile device, must control user access to/execution of all core and preinstalled applications, or the mobile device must provide an alternate method of restricting user access to/execution of core and preinstalled applications. 

Core application: Any application integrated into the operating system by the operating system or mobile device vendors. 

Preinstalled application: Additional noncore applications included in the operating system build by the operating system vendor, mobile device vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review device configuration settings to confirm that the system application disable list has been configured to include all system apps that have been identified as having non-DoD-approved characteristics. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox application" group, verify that the system application disable list contains all apps identified as having non-DoD-approved characteristics. 

On the Samsung Android device, review the apps on the "Personal" App screen and confirm that none of the apps listed in the system application disable list are present. 

If the system application disable list does not contain all the apps that have been identified as having non-DoD-approved characteristics, or if an app listed can be found on the "Personal" App screen of the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to include all system apps in the system app disable list that have been identified as having non-DoD-approved characteristics. 

The system application disable list controls user access to/execution of core and preinstalled applications. It does not control the installation of applications. 

On the MDM console, for the device, in the "Knox application" group, add all system app packages that have been identified as having non-DoD-approved characteristics to the system application disable list. 

Note: Refer to the "System Apps for Disablement (Non-DoD-Approved Characteristics)" and "System Apps That Must Not Be Disabled" tables in the Supplemental document for this STIG.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92959'
  tag rid: 'SV-103047r1_rule'
  tag stig_id: 'KNOX-09-000105'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-99205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
