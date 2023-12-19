control 'SV-103841' do
  title 'The Samsung Android whitelist must be configured to not include applications with the following characteristic: - transmit MD diagnostic data to non-DoD servers.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment. 

Application note: The application whitelist, in addition to controlling the installation of applications on the mobile device, must control user access to/execution of all core and preinstalled applications, or the mobile device must provide an alternate method of restricting user access to/execution of core and preinstalled applications. 

Core application: Any application integrated into the operating system by the operating system or mobile device vendors. 

Preinstalled application: Additional noncore applications included in the operating system build by the operating system vendor, mobile device vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review device configuration settings to confirm that the system application disable list has been configured to include all system apps that have been identified to transmit mobile device diagnostic data to non-DoD servers. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

Confirm if Method #1 or Method #2 is used at the Samsung device site, and follow the appropriate procedure. 

**** 

Method #1: On the MDM console, for the device, in the "managed Google Play" group, verify that the system application disable list contains all apps identified to transmit mobile device diagnostic data to non-DoD servers. 

On the Samsung Android device, review the apps on the "Personal" App screen and confirm that none of the apps listed in the system application disable list are present. 

If the system application disable list does not contain all the apps that have been identified to transmit mobile device diagnostic data to non-DoD servers, or if an app listed can be found on the "Personal" App screen of the Samsung Android device, this is a finding. 

**** 

Method #2: On the MDM console, for the device, in the "Knox application" group, verify that the system application disable list contains all apps identified to transmit mobile device diagnostic data to non-DoD servers. 

On the Samsung Android device, review the apps on the "Personal" App screen and confirm that none of the apps listed in the system application disable list are present. 

If the system application disable list does not contain all the apps that have been identified to transmit mobile device diagnostic data to non-DoD servers, or if an app listed can be found on the "Personal" App screen of the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to include all system apps in the system app disable list that have been identified to transmit mobile device diagnostic data to non-DoD servers. 

Do one of the following: 
- Method # 1 (preferred): Use managed Google Play for the device (managed device). 
- Method #2: Use the Knox system application disable list. 

**** 

Method #1: On the MDM console, for the device, in the "managed Google Play" group, add all system app packages that have been identified to transmit mobile data diagnostic data to non-DoD servers to the system application disable list. 

**** 

Method #2: On the MDM console, for the device, in the "Knox application" group, add all system app packages that have been identified to transmit mobile device diagnostic data to non-DoD servers to the system application disable list. 

**** 

Note: Refer to the "System Apps for Disablement (Non-DoD-Approved Characteristics)" and "System Apps That Must Not Be Disabled" tables in the Supplemental document for this STIG. Only system apps that are identified with the characteristic of "transmit MD diagnostic data to non-DoD servers" need to be added to the system application disable list.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93073r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93755'
  tag rid: 'SV-103841r1_rule'
  tag stig_id: 'KNOX-09-000110'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-100001r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
