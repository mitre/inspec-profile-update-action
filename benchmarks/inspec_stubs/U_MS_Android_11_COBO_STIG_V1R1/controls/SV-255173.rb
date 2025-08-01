control 'SV-255173' do
  title 'Microsoft Android 11 must be configured to enforce an application installation policy by specifying an application allow list that restricts applications by the following characteristics: [selection: list of digital signatures, cryptographic hash values, names, application version].'
  desc 'The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application allow list prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allow list. Failure to configure an application allow list properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DOD data accessible by these applications.

The application allow list, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and preinstalled applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device has an application allow list configured. Verify all applications listed on the allow list have been approved by the Approving Official (AO).

This validation procedure is performed both on the EMM Administration console and mobile device.

On the EMM console:
1. Go to the Android app catalog for managed Google Play.
2. Verify all selected apps are AO-approved.

On the Microsoft Android 11 device:
Open the managed Google Play store and verify that only the approved apps are visible.

Note: Managed Google Play is always an allow listed App Store.

If on the EMM console the list of selected Managed Google Play apps included non-approved apps, this is a finding.

Note: The application allow list will include approved core applications (included in the OS by the OS vendor) and preinstalled applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications. For Microsoft Android, there are no preinstalled applications.'
  desc 'fix', 'Configure the Microsoft Android 11 device to use an application allow list.

On the EMM console:
1. Go to the Android app catalog for managed Google Play.
2. Select apps to be available (only approved apps).
3. Push updated policy to the device.

Note: Managed Google Play is always a allow listed App Store.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58786r870657_chk'
  tag severity: 'medium'
  tag gid: 'V-255173'
  tag rid: 'SV-255173r870659_rule'
  tag stig_id: 'MSFT-11-001000'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-58730r870658_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
