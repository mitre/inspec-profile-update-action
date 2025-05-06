control 'SV-251822' do
  title 'Samsung Android must be configured to not allow installation of applications with the following characteristics: - back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);- transmit MD diagnostic data to non-DoD servers; - voice assistant application if available when MD is locked; - voice dialing application if available when MD is locked; - allows synchronization of data or applications between devices associated with user; and - allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application allowlist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allowlist. Failure to configure an application allowlist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. Applications with the listed characteristics have features that can cause the compromise of sensitive DoD data or have features with no known application in the DoD environment.

Application note: The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Verify requirement KNOX-12-110190 (managed Google Play) has been implemented.

If "managed Google Play" has not been implemented, this is a finding.'
  desc 'fix', 'The Authorizing Official (AO) must not approve applications with the following characteristics for installation by users in the Device:

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user;
- payment processing; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

Implement "managed Google Play" (see requirement KNOX-12-110190).'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55282r816520_chk'
  tag severity: 'medium'
  tag gid: 'V-251822'
  tag rid: 'SV-251822r816522_rule'
  tag stig_id: 'KNOX-12-110200'
  tag gtitle: 'PP-MDF-323070'
  tag fix_id: 'F-55236r816521_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
