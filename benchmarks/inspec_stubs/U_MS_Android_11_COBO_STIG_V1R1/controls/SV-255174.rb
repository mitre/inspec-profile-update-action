control 'SV-255174' do
  title 'Microsoft Android 11 allow list must be configured to not include applications with the following characteristics: 

- Back up MD data to non-DOD cloud servers (including user and application access to cloud backup services);
- Transmit MD diagnostic data to non-DOD servers;
- Voice assistant application if available when MD is locked;
- Voice dialing application if available when MD is locked;
- Allows synchronization of data or applications between devices associated with user; and
- Allows unencrypted (or encrypted but not FIPS 140-2/FIPS 140-3 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application allow list prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allow list. Failure to configure an application allow list properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DOD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DOD data or have features with no known application in the DOD environment.

Application note: The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device has an application allow list configured and that the application allow list does not include applications with the following characteristics:

- Back up MD data to non-DOD cloud servers (including user and application access to cloud backup services);
- Transmit MD diagnostic data to non-DOD servers;
- Voice assistant application if available when MD is locked;
- Voice dialing application if available when MD is locked;
- Allows synchronization of data or applications between devices associated with user;
- Payment processing; and
- Allows unencrypted (or encrypted but not FIPS 140-2/FIPS 140-3 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

This validation procedure is performed only on the EMM Administration console.

On the EMM console:
1. Review the list of selected Managed Google Play apps.
2. Review the details and privacy policy of each selected app to ensure the app does not include prohibited characteristics.

If the EMM console device policy includes applications with unauthorized characteristics, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device application allow list to exclude applications with the following characteristics:

- Back up MD data to non-DOD cloud servers (including user and application access to cloud backup services);
- Transmit MD diagnostic data to non-DOD servers;
- Voice assistant application if available when MD is locked;
- Voice dialing application if available when MD is locked;
- Allows synchronization of data or applications between devices associated with user;
- Payment processing; and
- Allows unencrypted (or encrypted but not FIPS 140-2/FIPS 140-3 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

On the EMM console:
1. Go to the Android app catalog for managed Google Play.
2. Before selecting an app, review the app details and privacy policy to ensure the app does not include prohibited characteristics.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58787r870660_chk'
  tag severity: 'medium'
  tag gid: 'V-255174'
  tag rid: 'SV-255174r870662_rule'
  tag stig_id: 'MSFT-11-001100'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-58731r870661_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
