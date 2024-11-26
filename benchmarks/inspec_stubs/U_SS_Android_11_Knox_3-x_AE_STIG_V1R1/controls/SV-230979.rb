control 'SV-230979' do
  title 'The Samsung Android Work Environment allowlist must be configured to not include applications with the following characteristics: 

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application allowlist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allowlist. Failure to configure an application allowlist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Samsung Android Work Environment configuration setting to determine if the application allowlist is configured to not include applications with the following characteristics: 

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.

The application allowlist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-10-009300.

This validation procedure is performed only on the management tool Administration Console.

On the management tool, in the Work Environment app catalog for managed Google Play, for each approved app, verify the app details and privacy policy to ensure the app does not include prohibited characteristics.

If on the management tool the Work Environment app catalog for managed Google Play includes apps with unauthorized characteristics, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to use an application allowlist to not include applications with the following characteristics: 

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.

The application allowlist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-10-009300.

On the management tool, in the Work Environment app catalog for managed Google Play, before adding an app, review the app details and privacy policy to ensure the app does not include prohibited characteristics.

NOTE: Managed Google Play is an allowed App Store.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33909r592429_chk'
  tag severity: 'medium'
  tag gid: 'V-230979'
  tag rid: 'SV-230979r607691_rule'
  tag stig_id: 'KNOX-11-001900'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-33882r592430_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
