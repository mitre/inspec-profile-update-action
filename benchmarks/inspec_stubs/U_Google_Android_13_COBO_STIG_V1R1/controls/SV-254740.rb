control 'SV-254740' do
  title 'Google Android 13 must be configured to enforce an application installation policy by specifying an application allowlist that restricts applications by the following characteristics: [selection: list of digital signatures, cryptographic hash values, names, application version].'
  desc 'The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application allowlist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allowlist. Failure to configure an application allowlist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DOD data accessible by these applications.

The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and preinstalled applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the mobile device has an application allowlist configured. Verify all applications listed on the allowlist have been approved by the Approving Official (AO).

On the EMM console:

COBO and COPE:

1. Go to the Android app catalog for managed Google Play.
2. Verify all selected apps are AO approved.

On the managed Google Android 13 device:

COBO and COPE:

1. Open the managed Google Play Store.
2. Verify that only the approved apps are visible.

Note: Managed Google Play is an allowed App Store.

If the EMM console list of selected managed Google Play apps includes non-approved apps, this is a finding.

Note: The application allowlist will include approved core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. For Google Android, there are no pre-installed applications.'
  desc 'fix', 'Configure the Google Android 13 device to use an application allowlist.

On the EMM Console:

COBO and COPE:

1. Go to the Android app catalog for managed Google Play.
2. Select apps to be available (only approved apps).
3. Push updated policy to the device.

Note: Managed Google Play is an allowed App Store.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58351r862417_chk'
  tag severity: 'medium'
  tag gid: 'V-254740'
  tag rid: 'SV-254740r862419_rule'
  tag stig_id: 'GOOG-13-006600'
  tag gtitle: 'PP-MDF-323060'
  tag fix_id: 'F-58297r862418_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
