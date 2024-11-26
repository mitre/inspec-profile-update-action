control 'SV-103043' do
  title 'Samsung Android must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 

Core application: Any application integrated into Samsung Android by Google or Samsung. 

Preinstalled application: Additional noncore applications included in the Samsung Android build by Google, Samsung, or the wireless carrier. 

Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. 

The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review device configuration settings to confirm that the system application disable list has been configured. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox application" group, verify the system application disable list contains all apps that have not been approved for DoD use by the Authorizing Official (AO). 

On the Samsung Android device, review the apps on the "Personal" App screen and confirm that none of the apps listed in the system application disable list are present. 

If the system application disable list does not contain all the apps that have not been approved by the AO, or if an app listed can be found on the "Personal" App screen of the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enforce the system application disable list. 

On the MDM console, for the device, in the "Knox application" group, add all non-AO-approved system app packages to the system application disable list. 

Note: Refer to the "System Apps for disablement (other characteristics)" and "System Apps That Must Not Be Disabled" tables in the Supplemental document for this STIG.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92955'
  tag rid: 'SV-103043r1_rule'
  tag stig_id: 'KNOX-09-000045'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-99201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
