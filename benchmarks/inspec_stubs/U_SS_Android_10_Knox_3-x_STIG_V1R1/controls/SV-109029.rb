control 'SV-109029' do
  title 'Samsung Android Work Environment must be configured to enforce an application installation policy by specifying an application whitelist that restricts applications by the following characteristics: names.'
  desc 'The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. 

Core application: Any application integrated into the OS by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review the Samsung Android Work Environment configuration setting to determine if the mobile device has an application whitelist configured. Verify that all applications listed on the whitelist have been approved by the Approving Official (AO).

This validation procedure is performed only on the management tool Administration Console.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

****

Method #1: Use managed Google Play [not available for KPE(Legacy) deployments].

On the management tool, in the Work Environment app catalog for managed Google Play, verify that only AO-approved apps are available.

If on the management tool the Work Environment app catalog for managed Google Play includes non-AO-approved apps, this is a finding.

****

Method #2: Use KPE app installation whitelisting.

On the management tool, in the Work Environment KPE restrictions section, verify that only AO-approved apps are listed in the "app installation whitelist".

If on the management tool the Work Environment "app installation whitelist" contains non-AO-approved apps, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to use an application whitelist.

The application whitelist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-10-009300.

Do one of the following:
- Method #1: Use managed Google Play [not available for KPE(Legacy) deployments].
- Method #2: Use KPE app installation whitelisting.

****

Method #1: Use managed Google Play [not available for KPE(Legacy) deployments].

On the management tool, in the Work Environment app catalog for managed Google Play, add each AO-approved app to be available.

****

Method #2: Use KPE app installation whitelisting.

On the management tool, in the Work Environment KPE restrictions section, add each AO-approved app to the "app installation whitelist".

Note: Refer to the management tool documentation to determine the following:
- If an application installation blacklist is also required to be configured when enforcing an "app installation whitelist"; and
- If the management tool supports adding apps to the "app installation whitelist" by package name and/or digital signature or supports a combination of the two.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99925'
  tag rid: 'SV-109029r1_rule'
  tag stig_id: 'KNOX-10-001000'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-105609r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
