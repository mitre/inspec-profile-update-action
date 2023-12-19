control 'SV-258644' do
  title 'Samsung Android must be configured to enforce an application installation policy by specifying an application allowlist that restricts applications by the following characteristics: Names.'
  desc 'The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

Preinstalled application: Additional noncore applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application allowlist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allowlist. Failure to configure an application allowlist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DOD data accessible by these applications.

The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and preinstalled applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and preinstalled applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are allowing users to install only applications that have been approved by the Authorizing Official (AO).

This validation procedure is performed only on the management tool.

On the management tool, in the app catalog for managed Google Play, verify only AO-approved apps are available.

If on the management tool the app catalog for managed Google Play includes non-AO-approved apps, this is a finding.'
  desc 'fix', 'Configure Samsung Android devices to allow users to install only applications that have been approved by the AO.

In addition to any local policy, the AO must not approve applications that have certain prohibited characteristics. These are covered in KNOX-14-110200.

On the management tool, in the app catalog for managed Google Play, add each AO-approved app to be available.

Note: Managed Google Play is an allowed App Store.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62384r931130_chk'
  tag severity: 'medium'
  tag gid: 'V-258644'
  tag rid: 'SV-258644r931132_rule'
  tag stig_id: 'KNOX-14-110190'
  tag gtitle: 'PP-MDF-333060'
  tag fix_id: 'F-62293r931131_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
