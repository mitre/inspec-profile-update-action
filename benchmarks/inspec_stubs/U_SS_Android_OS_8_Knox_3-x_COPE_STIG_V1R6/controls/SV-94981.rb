control 'SV-94981' do
  title 'Samsung Android 8 with Knox must be configured to enforce a CONTAINER application installation policy by specifying an application whitelist that restricts applications by the following characteristics: List of digital signatures, names.'
  desc 'The application whitelist, in addition to controlling the installation of applications on the mobile device (MD), must control user access/execution of all core and pre-installed applications, or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications. 

Core application: Any application integrated into the operating system (OS) by the OS or MD vendors.

Pre-installed application: Additional non-core applications included in the OS build by the OS vendor, MD vendor, or wireless carrier.

Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the OS by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has been configured to whitelist application installations into the CONTAINER based on one of the following characteristics:
- Digital signature
- Package name

Verify all applications listed on the whitelist have been approved by the Authorizing Official (AO).

This validation procedure is performed only on the MDM Administration Console.

On the MDM console, perform Steps 1 and 2 or Steps 3 and 4:
1. Ask the MDM Administrator to display the "Package Name Whitelist" in the "Android Knox CONTAINER >> CONTAINER Applications" rule.
2. Verify the whitelist includes only package names that the AO has approved.
3. Ask the MDM Administrator to display the "Signature Whitelist" in the "Android Knox CONTAINER >> CONTAINER Applications" rule.
4. Verify the whitelist includes only digital signatures the AO has approved.

Note: Either list may be empty if the AO has not approved any app.

Note: Refer to the Supplemental document for additional information.

If the MDM console "Package Name Whitelist" or "Signature Whitelist" contains non-AO-approved entries, this is a finding.

Note: The application Whitelist must be implemented so that only approved applications can be downloaded from the Google Play Store. Access to the Google Play Store must be enabled so that apps used by Google Play Services can be updated. The following app packages must be included in the CONTAINER app whitelist so that Google Play services can be updated:

• com.android.vending
• com.google.android.finsky
• com.google.android.gm
• com.google.android.gms
• com.google.android.gsf.login
• com.google.android.setupwizard
• com.google.android.gsf'
  desc 'fix', 'Configure Samsung Android 8 with Knox to whitelist application installations into the CONTAINER based on one of the following characteristics:
- Digital signature
- Package name

Both whitelists apply to user installable applications only and do not control user access/execution of core and pre-installed applications. To restrict user access/execution to core and pre-installed applications, the MDM Administrator must configure the "application disable list".

It is important to note that if the MDM Administrator has not blacklisted an application characteristic (package name, digital signature), it is implicitly whitelisted, as whitelists are exceptions to blacklists. If an application characteristic appears in both the blacklist and whitelist, the whitelist (as the exception to the blacklist) takes priority, and the user will be able to install the application. Therefore, the MDM Administrator must configure the blacklists to include all package names or digital signatures for whitelisting to behave as intended.

On the MDM console, do one of the following:
1. Add each AO-approved package name to the "Package Name Whitelist" in the "Android Knox CONTAINER >> CONTAINER Applications" rule.
2. Add each AO-approved digital signature to the "Signature Whitelist" in the "Android Knox CONTAINER >> CONTAINER Applications" rule.

Note: Either list may be empty if the AO has not approved any app.

Note: Refer to the Supplemental document for additional information.

Note: The application Whitelist must be implemented so that only approved applications can be downloaded from the Google Play Store. Access to the Google Play Store must be enabled so that apps used by Google Play Services can be updated. The following app packages must be included in the CONTAINER app whitelist so that Google Play services can be updated:

• com.android.vending
• com.google.android.finsky
• com.google.android.gm
• com.google.android.gms
• com.google.android.gsf.login
• com.google.android.setupwizard
• com.google.android.gsf'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80277'
  tag rid: 'SV-94981r1_rule'
  tag stig_id: 'KNOX-08-001400'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-87083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
