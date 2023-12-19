control 'SV-94979' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure CONTAINER application install blacklist.'
  desc 'Blacklisting all applications is required so only whitelisted applications can be installed on the device. Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist and blacklist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to Blacklist CONTAINER Application Install. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Package Name Blacklist" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule. 
2. Verify the setting is configured to all package names (specified by the wildcard string ".*").
3. Ask the MDM Administrator to display the "Signature Blacklist" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule. 
4. Verify the setting is configured to all digital signatures (specified by the wildcard string ".*").

On the Samsung Android 8 with Knox device, do the following:
1. Attempt to install any application that has not been whitelisted for installation by either package name or digital signature.
2. Verify that the application is blocked from being installed.

If the MDM console "Package Name Blacklist" or "Signature Blacklist" is not set to include all entries or on the Samsung Android 8 with Knox device, the user is able to install the application, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to Blacklist CONTAINER Application Install.

On the MDM console, do the following:
1. Add all package names by wildcard (".*") to the "Package Name Blacklist" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule.
2. Add all digital signatures by wildcard (".*") to the "Signature Blacklist" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80275'
  tag rid: 'SV-94979r1_rule'
  tag stig_id: 'KNOX-08-001100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87081r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
