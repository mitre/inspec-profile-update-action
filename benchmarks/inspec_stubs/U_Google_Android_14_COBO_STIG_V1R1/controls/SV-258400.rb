control 'SV-258400' do
  title 'The Google Android 14 work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 
 
Core application: Any application integrated into Google Android 14 by Google. 
 
Preinstalled application: Additional noncore applications included in the Google Android 14 build by Google or the wireless carrier. 
 
Some system applications can compromise DOD data or upload users' information to non-DOD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DOD data or DOD user information. 
 
The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DOD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the managed Google Android 14 work profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. Verify only approved system apps have been placed on the core allowlist.
 
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
  desc 'fix', 'Configure the Google Android 14 device to enforce the system application disable list. 

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
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62141r928223_chk'
  tag severity: 'medium'
  tag gid: 'V-258400'
  tag rid: 'SV-258400r928225_rule'
  tag stig_id: 'GOOG-14-010200'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62065r928224_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
