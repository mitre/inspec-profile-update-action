control 'SV-254596' do
  title 'Apple iOS/iPadOS 16 allowlist must be configured to not include applications with the following characteristics: - Backs up MD data to non-DoD cloud servers (including user and application access to cloud backup services); - Transmits MD diagnostic data to non-DoD servers; - Allows synchronization of data or applications between devices associated with user; and - Allows unencrypted (or encrypted but not FIPS 140-2/FIPS 140-3 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application allow list prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allow list. Failure to configure an application allow list properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Verify no apps with the following prohibited characteristics are included in the configuration profile:

- backs up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmits MD diagnostic data to non-DoD servers;
- allows synchronization of data or applications between devices associated with user; and
- allows unencrypted (or encrypted but not FIPS 140-2/FIPS 140-3 validated) data sharing with other MDs or printers.

This check procedure is performed on the Apple iOS/iPadOS management tool. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow Listed App" (allowlistedAppBundelIDs) is configured and there are no apps with prohibited characteristics.

If "Allow listed apps" is not configured and contains apps with prohibited characteristics, this is a finding.'
  desc 'fix', 'Install a configuration profile with an allow list of approved apps (allowlistedAppBundelIDs). Ensure the allow list does not include apps with the following characteristics:

- Backs up MD data to non-DoD cloud servers (including user and application access to cloud backup services).
- Transmits MD diagnostic data to non-DoD servers.
- Allows synchronization of data or applications between devices associated with user.
- Allows unencrypted (or encrypted but not FIPS 140-2/FIPS 140-3 validated) data sharing with other MDs or printers.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58207r862042_chk'
  tag severity: 'medium'
  tag gid: 'V-254596'
  tag rid: 'SV-254596r865866_rule'
  tag stig_id: 'AIOS-16-007400'
  tag gtitle: 'PP-MDF-323070'
  tag fix_id: 'F-58153r865865_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
