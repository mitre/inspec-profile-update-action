control 'SV-235068' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to enforce an application installation policy by specifying an application whitelist that restricts applications by the following characteristics: [selection: list of digital signatures, cryptographic hash values, names, application version].'
  desc 'The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device has an application whitelist configured. Verify all applications listed on the whitelist have been approved by the Approving Official (AO).

This validation procedure is performed only on the MDM Administration console.

On the MDM console:
1. Go to the Android app catalog for managed Honeywell Play.
2. Verify all selected apps are AO approved.

NOTE: Managed Google Play is always a Whitelisted App Store.

If on the MDM console the list of selected Managed Honeywell Play apps included non-approved apps, this is a finding.

NOTE: The application whitelist will include approved core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. For Honeywell Android, there are no pre-installed applications.'
  desc 'fix', 'Configure the Honeywell Android device to use an application whitelist.

On the MDM console:
1. Go to the Android app catalog for managed Honeywell Play.
2. Select apps to be available (only approved apps).
3. Push updated policy to the device.

NOTE: Managed Honeywell Play is always a Whitelisted App Store.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38287r623219_chk'
  tag severity: 'medium'
  tag gid: 'V-235068'
  tag rid: 'SV-235068r626527_rule'
  tag stig_id: 'HONW-09-001000'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-38250r623220_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
