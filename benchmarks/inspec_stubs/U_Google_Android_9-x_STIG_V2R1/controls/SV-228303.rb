control 'SV-228303' do
  title 'Google Android Pie work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 

Core application: Any application integrated into Google Android Pie by Google. 

Preinstalled application: Additional noncore applications included in the Google Android Pie build by Google or the wireless carrier. 

Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. 

The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Google Android Pie Work Profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. What needs to happen is to verify only approved system apps have been placed on the core whitelist.

This procedure is performed on the MDM Administrator console. 

Review the system app white list and verify only approved apps are on the list.

If on the MDM console the system app white list contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure Google Android Pie Work Profile to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the MDM, configure a list of approved Google core and preinstalled apps in the core app white list.'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30536r494976_chk'
  tag severity: 'medium'
  tag gid: 'V-228303'
  tag rid: 'SV-228303r494978_rule'
  tag stig_id: 'GOOG-09-009400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30521r494977_fix'
  tag 'documentable'
  tag legacy: ['SV-106459', 'V-97355']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
