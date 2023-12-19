control 'SV-235086' do
  title 'Honeywell Mobility Edge Android Pie devices work profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 
 
Core application: Any application integrated into Honeywell Mobility Edge Android Pie devices by Honeywell. 
 
Preinstalled application: Additional noncore applications included in the Honeywell Mobility Edge Android Pie device build by Honeywell or the wireless carrier. 
 
Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. 
 
The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Honeywell Mobility Edge Android Pie devices Work Profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. What needs to happen is to verify only approved system apps have been placed on the core whitelist.
 
This procedure is performed on the MDM Administrator console. 
 
Review the system app whitelist and verify only approved apps are on the list.

If on the MDM console the system app whitelist contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure Honeywell Mobility Edge Android Pie devices Work Profile to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the MDM, configure a list of approved Honeywell core and preinstalled apps in the core app whitelist.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38305r623273_chk'
  tag severity: 'medium'
  tag gid: 'V-235086'
  tag rid: 'SV-235086r626527_rule'
  tag stig_id: 'HONW-09-009400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38268r623274_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
