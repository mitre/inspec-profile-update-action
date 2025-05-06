control 'SV-231018' do
  title 'Samsung Android Work Environment must be configured to enforce an application installation policy by specifying an application allowlist that restricts applications by the following characteristics: names.'
  desc 'The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application allowlist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the allowlist. Failure to configure an application allowlist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application allowlist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review the Samsung Android Work Environment configuration setting to determine if the mobile device has an application allowlist configured. Verify that all applications listed on the allowlist have been approved by the Approving Official (AO).

This validation procedure is performed only on the management tool Administration Console.

On the management tool, in the Work Environment KPE restrictions section, verify that only AO-approved apps are listed in the "app installation allowlist".

If on the management tool the Work Environment "app installation allowlist" contains non-AO-approved apps, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to use an application allowlist.

The application allowlist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-10-009300.

On the management tool, in the Work Environment KPE application section, add each AO-approved app to the "app installation allowlist".

NOTE: Refer to the management tool documentation to determine the following:
- If an application installation denylist is also required to be configured when enforcing an "app installation allowlist"; and
- If the management tool supports adding apps to the "app installation allowlist" by package name and/or digital signature or supports a combination of the two.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33948r592668_chk'
  tag severity: 'medium'
  tag gid: 'V-231018'
  tag rid: 'SV-231018r608683_rule'
  tag stig_id: 'KNOX-11-001800'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-33921r592669_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
