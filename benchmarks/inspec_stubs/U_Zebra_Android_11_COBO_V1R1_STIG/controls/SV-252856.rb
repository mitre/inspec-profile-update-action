control 'SV-252856' do
  title 'Zebra Android 11 must be configured to enforce an application installation policy by specifying an application allow list that restricts applications by the following characteristics: [selection: list of digital signatures, cryptographic hash values, names, application version].'
  desc 'The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application allow list prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allow list. Failure to configure an application allow list properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Zebra Android device configuration settings to determine if the mobile device has an application allow list configured. Verify all applications listed on the allow list have been approved by the Approving Official (AO).

On the EMM console, do the following:
1. Go to the Android app catalog for managed Google Play.
2. Verify all selected apps are AO approved.

On the Android 11 device, do the following:
1. Open the managed Google Play store.
2. Verify that only the approved apps are visible.

Note: Managed Google Play is an allowed App Store.

If the EMM console list of selected Managed Google Play apps includes non-approved apps, this is a finding.

Note: The application allow list will include approved core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. For Zebra Android, there are no pre-installed applications.'
  desc 'fix', 'Configure the Zebra Android 11 device to use an application allow list.

On the EMM Console:
1. Go to the Android app catalog for managed Google Play.
2. Select apps to be available (only approved apps).
3. Push updated policy to the device.

Note: Managed Google Play is an allowed App Store.'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56312r820493_chk'
  tag severity: 'medium'
  tag gid: 'V-252856'
  tag rid: 'SV-252856r820495_rule'
  tag stig_id: 'ZEBR-11-001000'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-56262r820494_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001776']
  tag nist: ['CM-6 b', 'CM-7 (5) (c)']
end
