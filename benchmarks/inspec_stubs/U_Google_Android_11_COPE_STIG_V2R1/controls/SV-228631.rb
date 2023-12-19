control 'SV-228631' do
  title 'Google Android 11 work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 
 
Core application: Any application integrated into Google Android 11 by Google. 
 
Preinstalled application: Additional noncore applications included in the Google Android 11 build by Google or the wireless carrier. 
 
Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. 
 
The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Google Android 11 Work Profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. Verify only approved system apps have been placed on the core allow list.
 
This procedure is performed on the EMM Administrator console. 
 
Review the system app allow list and verify only approved apps are on the list.

1. Open "Apps management" section.
2. Select "Hide apps on parent".
3. Verify package names of apps.

If on the EMM console the system app allow list contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure Google Android 11 device Work to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the EMM console:
1. Open "Apps management" section.
2. Select "Hide apps on parent".
3. Enter package names of apps.

Configure a list of approved Google core and preinstalled apps in the core app allow list.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COPE'
  tag check_id: 'C-30866r505890_chk'
  tag severity: 'medium'
  tag gid: 'V-228631'
  tag rid: 'SV-228631r619923_rule'
  tag stig_id: 'GOOG-11-009400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30843r505891_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
