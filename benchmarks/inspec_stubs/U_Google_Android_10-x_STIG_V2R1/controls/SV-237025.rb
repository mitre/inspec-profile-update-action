control 'SV-237025' do
  title 'Google Android 10 work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 

Core application: Any application integrated into Google Android 10 by Google. 

Preinstalled application: Additional noncore applications included in the Google Android 10 build by Google or the wireless carrier. 

Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. 

The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Google Android 10 Work Profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. What needs to happen is to verify only approved system apps have been placed on the core whitelist.

This procedure is performed on the MDM Administrator console. 

Review the system app white list and verify only approved apps are on the list.

If on the MDM console the system app white list contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure Google Android 10 Work Profile to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the MDM, configure a list of approved Google core and preinstalled apps in the core app white list.'
  impact 0.5
  ref 'DPMS Target Google Android 10-x'
  tag check_id: 'C-40244r639219_chk'
  tag severity: 'medium'
  tag gid: 'V-237025'
  tag rid: 'SV-237025r639221_rule'
  tag stig_id: 'GOOG-10-009400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40207r639220_fix'
  tag 'documentable'
  tag legacy: ['SV-108075', 'V-98971']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
