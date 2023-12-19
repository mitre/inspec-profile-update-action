control 'SV-241199' do
  title 'The Samsung Android Work Environment whitelist must be configured to not include applications with the following characteristics: - back up MD data to non-DoD cloud servers (including user and application access to cloud backup services); - transmit MD diagnostic data to non-DoD servers; - voice assistant application if available when MD is locked; - voice dialing application if available when MD is locked; - allows synchronization of data or applications between devices associated with user; and - allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Samsung Android Work Environment configuration setting to determine if the application whitelist is configured to not include applications with the following characteristics: 

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.

The application whitelist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-10-009300.

This validation procedure is performed only on the management tool Administration Console.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

****

Method #1: Use managed Google Play [not available for KPE(Legacy) deployments].

On the management tool, in the Work Environment app catalog for managed Google Play, for each approved app, verify the app details and privacy policy to ensure the app does not include prohibited characteristics.

If on the management tool the Work Environment app catalog for managed Google Play includes apps with unauthorized characteristics, this is a finding.

****

Method #2: Use KPE app installation whitelisting.

On the management tool, in the Work Environment KPE restrictions section, for each approved app on the "app installation whitelist", review the app details and privacy policy to ensure the app does not include prohibited characteristics.

If on the management tool the Work Environment "app installation whitelist" includes apps with unauthorized characteristics, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to use an application whitelist to not include applications with the following characteristics: 

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.

The application whitelist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-10-009300.

Do one of the following:
- Method #1: Use managed Google Play [not available for KPE(Legacy) deployments].
- Method #2: Use KPE app installation whitelisting.

****

Method #1: Use managed Google Play [not available for KPE(Legacy) deployments].

On the management tool, in the Work Environment app catalog for managed Google Play, before adding an app, review the app details and privacy policy to ensure the app does not include prohibited characteristics.

****

Method #2: Use KPE app installation whitelisting.

On the management tool, in the Work Environment KPE restrictions section, before adding an app to the "app installation whitelist", review the app details and privacy policy to ensure the app does not include prohibited characteristics.

Note: Refer to the management tool documentation to determine the following:
- If an application installation blacklist is also required to be configured when enforcing an "app installation whitelist"; and
- If the management tool supports adding apps to the "app installation whitelist" by package name and/or digital signature or supports a combination of the two.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44475r680236_chk'
  tag severity: 'medium'
  tag gid: 'V-241199'
  tag rid: 'SV-241199r852767_rule'
  tag stig_id: 'KNOX-10-001100'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-44434r680237_fix'
  tag 'documentable'
  tag legacy: ['SV-109031', 'V-99927']
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
