control 'SV-91223' do
  title 'The Samsung Android 7 with Knox must be configured to enforce an application installation policy by specifying an application whitelist that restricts applications by either of the following characteristics: list of digital signatures, list of package names.'
  desc 'The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core and preinstalled applications or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. Core application - any application integrated into the operating system (OS) by the OS or mobile device (MD) vendors. Pre-installed application - additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the operating system (OS) by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Note, this requirement is Not Applicable if the AO has approved an unmanaged personal container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has been configured to whitelist application installations based on one of the following characteristics:
- Digital signature
- Package Name

Verify all applications listed on the whitelist have been approved by the Approving Official (AO).

This validation procedure is performed only on the MDM Administration Console.

On the MDM console, do the following (do 1 & 2 or 3 & 4):
1. Ask the MDM administrator to display the "Package Name Whitelist" in the "Android Applications" rule.
2. Verify the whitelist includes only package names that the Authorizing Official (AO) has approved.
OR
3. Ask the MDM administrator to display the "Signature Whitelist" in the "Android Applications" rule.
4. Verify the whitelist includes only digital signatures the Authorizing Official (AO) has approved.

Note: Either list may be empty if the Authorizing Official (AO) has not approved any apps.

Note: Refer to the Supplemental document for additional information.

If the MDM console "Package Name Whitelist" or "Signature Whitelist" contains non-AO approved entries, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox device to whitelist application installations based on the one of the following characteristics:
- Digital signature
- Package Name

Both whitelists apply to user installable applications only, and do not control user access/execution of core and preinstalled applications. To restrict user access/execution to core and pre-installed applications, the MDM administrator must configure the "application disable list”.

It is important to note that if the MDM administrator has not blacklisted an application characteristic (package name, digital signature) then it is implicitly whitelisted, as whitelists are exceptions to blacklists. If an application characteristic appears in both the blacklist and whitelist, the white list (as the exception to the blacklist) takes priority, and the User will be able to install the application. Therefore, the MDM administrator must configure the blacklists to include all package names and digital signatures for whitelisting to behave as intended. Note that some MDM vendors have implemented the blacklist function described above behind the scenes and there may not be a blacklist function to configure by the system administrator.

On the MDM console, do one of the following:
1. Add each AO-approved package name to the "Package Name Whitelist" in the "Android Applications" rule.
2. Add each AO-approved digital signature to the "Signature Whitelist" in the "Android Applications" rule.

Note: Either list may be empty if the Authorizing Official (AO) has not approved any apps.

Note: Refer to the Supplemental document for additional information.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76527'
  tag rid: 'SV-91223r1_rule'
  tag stig_id: 'KNOX-07-001400'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-83209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
