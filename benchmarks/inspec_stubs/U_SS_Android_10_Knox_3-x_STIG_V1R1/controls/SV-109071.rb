control 'SV-109071' do
  title 'Samsung Android Work Environment must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access/execution of all core and pre-installed applications.

Core application: Any application integrated into Samsung Android by Google or Samsung.

Pre-installed application: Additional non-core applications included in the Samsung Android build by Google, Samsung, or the wireless carrier.

Some system applications can compromise DoD data or upload user's information to non-DoD-approved servers. A user must be blocked from using applications that exhibit behavior that can result in compromise of DoD data or DoD user information.

The site Administrator must analyze all pre-installed applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the system application disable list is enforced.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: KPE(AE) enrollment

The required configuration is the default configuration when the device is enrolled as a KPE(AE) deployment.

On the management tool, verify that the Work Environment "core app white list" contains only approved core and preinstalled apps.

On the Samsung Android device, review the Work Environment apps and confirm that apps listed in the "System Apps for disablement" table in the Supplemental document are not present.

If on the management tool the "core app white list" contains non-approved core and preinstalled apps, or on the Samsung Android device non-approved apps are listed, this is a finding.

****

Method #2: KPE system app disable list

On the management tool, in the Work Environment KPE application section, verify that the "system app disable list" contains all apps that have not been approved for DoD use by the Authorizing Official (AO).

On the Samsung Android device, review the Work Environment apps and confirm that none of the apps listed in the “system app disable list” are present.

If on the management tool the "system app disable list" contains non-approved core and preinstalled apps, or on the Samsung Android device non-approved apps are listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to enforce the system application disable list. Refer to the “System Apps for disablement" table in the Supplemental document.

Do one of the following:
- Method #1: KPE(AE) enrollment
- Method #2: KPE system app disable list

****

Method #1: KPE(AE) enrollment

The required configuration is the default configuration when the device is enrolled as a KPE(AE) deployment.

If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the management tool, configure a list of approved Google core and preinstalled apps in the core app white list.

****

Method #2: KPE system app disable list

On the management tool, in the Work Environment KPE application section, add all non-AO-approved system app packages to the "system app disable list".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99967'
  tag rid: 'SV-109071r1_rule'
  tag stig_id: 'KNOX-10-009300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-105651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
