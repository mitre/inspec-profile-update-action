control 'SV-254741' do
  title 'Google Android 13 allowlist must be configured to not include applications with the following characteristics: 

1. Back up mobile device (MD) data to non-DOD cloud servers (including user and application access to cloud backup services);
2. Transmit MD diagnostic data to non-DOD servers;
3. Voice assistant application if available when MD is locked;
4. Voice dialing application if available when MD is locked;
5. Allows synchronization of data or applications between devices associated with user; and
6. Allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application allowlist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allowlist. Failure to configure an application allowlist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DOD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DOD data or have features with no known application in the DOD environment.

Application Note: The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the mobile device has an application allowlist configured and that the application allowlist does not include applications with the following characteristics:

- Back up MD data to non-DOD cloud servers (including user and application access to cloud backup services);
- Transmit MD diagnostic data to non-DOD servers;
- Voice assistant application if available when MD is locked;
- Voice dialing application if available when MD is locked;
- Allows synchronization of data or applications between devices associated with user;
- Payment processing; and
- Allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

This validation procedure is performed only on the EMM Administration Console.

On the EMM console:

1. Review the list of selected Managed Google Play apps.
2. Review the details and privacy policy of each selected app to ensure the app does not include prohibited characteristics.

If the EMM console device policy includes applications with unauthorized characteristics, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device application allowlist to exclude applications with the following characteristics:

- Back up MD data to non-DOD cloud servers (including user and application access to cloud backup services);
- Transmit MD diagnostic data to non-DOD servers;
- Voice assistant application if available when MD is locked;
- Voice dialing application if available when MD is locked;
- Allows synchronization of data or applications between devices associated with user;
- Payment processing; and
- Allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

On the EMM Console:

1. Go to the Android app catalog for managed Google Play.
2. Before selecting an app, review the app details and privacy policy to ensure the app does not include prohibited characteristics.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58352r862420_chk'
  tag severity: 'medium'
  tag gid: 'V-254741'
  tag rid: 'SV-254741r862422_rule'
  tag stig_id: 'GOOG-13-006700'
  tag gtitle: 'PP-MDF-323070'
  tag fix_id: 'F-58298r862421_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
