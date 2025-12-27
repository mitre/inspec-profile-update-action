control 'SV-231039' do
  title 'Samsung Android Work Environment must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access/execution of all core and pre-installed applications.

Core application: Any application integrated into Samsung Android by Google or Samsung.

Pre-installed application: Additional non-core applications included in the Samsung Android build by Google, Samsung, or the wireless carrier.

Some system applications can compromise DoD data or upload user's information to non-DoD-approved servers. A user must be blocked from using applications that exhibit behavior that can result in compromise of DoD data or DoD user information.

The site Administrator must analyze all pre-installed applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the system application disable list is enforced.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work Environment application section, verify that the "system app disable list" contains all apps that have not been approved for DoD use by the Authorizing Official (AO).

On the Samsung Android device, review the Work Environment apps and confirm that only apps that have been approved for DoD use by the Authorizing Official (AO) are listed.

If on the management tool the "system app disable list" contains non-approved core and preinstalled apps, or on the Samsung Android device non-approved apps are listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to enforce the system application disable list.

On the management tool, in the Work Environment application section, add all non-AO-approved system app packages to the "system app disable list".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33969r592731_chk'
  tag severity: 'medium'
  tag gid: 'V-231039'
  tag rid: 'SV-231039r608683_rule'
  tag stig_id: 'KNOX-11-018000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33942r592732_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
