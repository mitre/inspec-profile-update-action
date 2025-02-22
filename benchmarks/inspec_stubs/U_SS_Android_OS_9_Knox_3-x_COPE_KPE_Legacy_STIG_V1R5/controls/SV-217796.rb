control 'SV-217796' do
  title 'The Samsung Android whitelist must be configured to not include applications with the following characteristic: - transmit MD diagnostic data to non-DoD servers.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment. 

Application note: The application whitelist, in addition to controlling the installation of applications on the mobile device, must control user access to/execution of all core and preinstalled applications, or the mobile device must provide an alternate method of restricting user access to/execution of core and preinstalled applications. 

Core application: Any application integrated into the operating system by the operating system or mobile device vendors. 

Preinstalled application: Additional noncore applications included in the operating system build by the operating system vendor, mobile device vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review device configuration settings to confirm that the system application disable list has been configured to include all system apps that have been identified to transmit mobile device diagnostic data to non-DoD servers. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox application" group, verify that the system application disable list contains all apps identified to transmit mobile device diagnostic data to non-DoD servers. 

On the Samsung Android device, review the apps on the "Personal" App screen and confirm that none of the apps listed in the system application disable list are present. 

If the system application disable list does not contain all the apps that have been identified to transmit mobile device diagnostic data to non-DoD servers, or if an app listed can be found on the "Personal" App screen of the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to include all system apps in the system app disable list that have been identified to transmit mobile device diagnostic data to non-DoD servers. 

The system application disable list controls user access to/execution of core and preinstalled applications. It does not control the installation of applications. 

On the MDM console, for the device, in the "Knox application" group, add all system app packages that have been identified to transmit mobile device diagnostic data to non-DoD servers to the system application disable list. 

Note: Refer to the "System Apps for Disablement (Non-DoD-Approved Characteristics)" and "System Apps That Must Not Be Disabled" tables in the Supplemental document for this STIG. Only system apps that are identified with the characteristic of "transmit mobile MD diagnostic data to non-DoD servers" need to be added the system application disable list.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19012r362846_chk'
  tag severity: 'medium'
  tag gid: 'V-217796'
  tag rid: 'SV-217796r617473_rule'
  tag stig_id: 'KNOX-09-000115'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-19010r362847_fix'
  tag 'documentable'
  tag legacy: ['SV-103939', 'V-93853']
  tag cci: ['CCI-001806', 'CCI-000366']
  tag nist: ['CM-11 b', 'CM-6 b']
end
