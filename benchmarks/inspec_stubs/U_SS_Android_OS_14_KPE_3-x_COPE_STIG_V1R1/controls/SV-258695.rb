control 'SV-258695' do
  title 'The Samsung Android device work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 
 
Core application: Any application integrated into Samsung Android 14 by Samsung. 
 
Preinstalled application: Additional noncore applications included in the Samsung Android 14 build by Samsung or the wireless carrier. 
 
Some system applications can compromise DOD data or upload users' information to non-DOD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DOD data or DOD user information. 
 
The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DOD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the configuration to confirm the system application disable list is enforced. This setting is enforced by default. Verify only approved system apps have been placed on the core allowlist.
 
This procedure is performed on the management tool. 
 
Review the system app allowlist and verify only approved apps are on the list.

On the management tool, in the Apps management section, select "Unhide apps" and verify the names of the apps listed.

If on the management tool the system app allowlist contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 14 device to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the management tool:
1. Open "Apps management" section.
2. Select "Hide apps".
3. Enter names of apps to hide.

Configure a list of approved Samsung core and preinstalled apps in the core app allowlist.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62435r931283_chk'
  tag severity: 'medium'
  tag gid: 'V-258695'
  tag rid: 'SV-258695r931285_rule'
  tag stig_id: 'KNOX-14-225030'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62344r931284_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
