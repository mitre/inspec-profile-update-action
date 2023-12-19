control 'SV-217703' do
  title 'Samsung Android must be configured to enforce an application installation policy by specifying an application whitelist that restricts applications by the following characteristics: list of digital signatures, list of package names.'
  desc 'The application whitelist, in addition to controlling the installation of applications on the mobile device, must control user access to/execution of all core and preinstalled applications, or the mobile device must provide an alternate method of restricting user access to/execution of core and preinstalled applications. 

Core application: Any application integrated into the operating system by the operating system or mobile device vendors. 

Preinstalled application: Additional noncore applications included in the operating system build by the operating system vendor, mobile device vendor, or wireless carrier. 

Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications. 

The application whitelist, in addition to controlling the installation of applications on the mobile device, must control user access to/execution of all core applications (included in the operating system by the operating system vendor) and preinstalled applications (provided by the mobile device vendor and wireless carrier), or the mobile device must provide an alternate method of restricting user access to/execution of core and preinstalled applications.

SFR ID: FMT_SMF_EXT.1.1 #8b'
  desc 'check', 'Review device configuration settings to confirm that an application installation whitelist has been configured. 

This procedure is performed only on the MDM Administration console. 

On the MDM console, for the device, in the "Knox application" group, verify that each package listed on the application installation whitelist has been approved for DoD use by the Authorizing Official (AO). 

If the application installation whitelist contains non-AO-approved packages, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enforce an application installation whitelist. 

The application installation whitelist does not control user access to/execution of all core and preinstalled applications, and guidance for doing so is covered in KNOX-09-000055. 

On the MDM console, for the device, in the "Knox application" group, add each AO-approved package to the application installation whitelist. 

Refer to the MDM documentation to determine the following: 
- If an application installation blacklist is also required to be configured when enforcing an application installation whitelist. 
- If the MDM supports adding packages to the application installation whitelist by package name and/or digital signature or supports a combination of the two. 

Note: Refer to the "System Apps That Must Not Be Disabled" table in the Supplemental document for this STIG. These apps must be included in the application installation whitelist to allow updates.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18921r362257_chk'
  tag severity: 'medium'
  tag gid: 'V-217703'
  tag rid: 'SV-217703r617472_rule'
  tag stig_id: 'KNOX-09-000075'
  tag gtitle: 'PP-MDF-301090'
  tag fix_id: 'F-18919r362258_fix'
  tag 'documentable'
  tag legacy: ['SV-103045', 'V-92957']
  tag cci: ['CCI-001806', 'CCI-000366']
  tag nist: ['CM-11 b', 'CM-6 b']
end
