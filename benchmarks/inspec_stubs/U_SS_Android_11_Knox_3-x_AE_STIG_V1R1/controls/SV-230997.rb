control 'SV-230997' do
  title 'Samsung Android Personal Environment must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access/execution of all core and pre-installed applications.

Core application: Any application integrated into Samsung Android by Google or Samsung.

Pre-installed application: Additional non-core applications included in the Samsung Android build by Google, Samsung, or the wireless carrier.

Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using applications that exhibit behavior that can result in compromise of DoD data or DoD user information.

The site Administrator must analyze all pre-installed applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android Personal Environment configuration settings to determine if the system application disable list is enforced.

This procedure is only for the Personal Environment of a COPE deployment.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

The required configuration is the default configuration when the device is enrolled as an AE deployment.

On the management tool, verify that the "core app allowlist" contains only approved core and preinstalled apps.

On the Samsung Android device, review the Personal Environment apps and confirm that only approved core and preinstalled apps are listed.

If on the management tool the "core app allowlist" contains non-approved core and preinstalled apps, or on the Samsung Android device non-approved apps are listed, this is a finding.'
  desc 'fix', 'Configure the Samsung Android device to enforce the system application disable list.

This guidance is only for the Personal Environment of a COPE deployment.

The required configuration is the default configuration when the device is enrolled as an AE deployment.

If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the management tool, configure a list of approved Google core and preinstalled apps in the core app allowlist.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33927r592483_chk'
  tag severity: 'medium'
  tag gid: 'V-230997'
  tag rid: 'SV-230997r607691_rule'
  tag stig_id: 'KNOX-11-017700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33900r592484_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
