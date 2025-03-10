control 'SV-254756' do
  title 'The Google Android 13 work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 
 
Core application: Any application integrated into Google Android 13 by Google. 
 
Preinstalled application: Additional noncore applications included in the Google Android 13 build by Google or the wireless carrier. 
 
Some system applications can compromise DOD data or upload users' information to non-DOD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DOD data or DOD user information. 
 
The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DOD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the managed Google Android 13 work profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. Verify only approved system apps have been placed on the core allowlist.
 
This procedure is performed on the EMM Administrator console. 
 
Review the system app allowlist and verify only approved apps are on the list.

COBO:

1. Open "Apps management" section.
2. Select "Hide apps".
3. Verify package names of apps are listed.

COPE:

1. Open "Apps management" section.
2. Select "Hide apps on parent".
3. Verify package names of apps are listed.

If on the EMM console the system app allowlist contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the EMM console:

COBO:

1. Open "Apps management" section.
2. Select "Hide apps".
3. Enter package names of apps to hide.

COPE:

1. Open "Apps management" section.
2. Select "Hide apps on parent".
3. Enter package names of apps to hide.

Configure a list of approved Google core and preinstalled apps in the core app allowlist.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58367r862465_chk'
  tag severity: 'medium'
  tag gid: 'V-254756'
  tag rid: 'SV-254756r862467_rule'
  tag stig_id: 'GOOG-13-010200'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58313r862466_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
