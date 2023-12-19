control 'SV-91273' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Configure application install blacklist.'
  desc 'Blacklisting all applications is required so that only whitelisted applications can be installed on the device. Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist and blacklist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Note, this requirement is Not Applicable if the AO has approved unmanaged personal space/container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is Blacklisting Application Install. 

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do 1 & 2 or 3 & 4:
1. Ask the MDM administrator to display the "Package Name Blacklist" setting in the "Android Applications" rule. 
2. Verify the setting is configured to include all package names (specified by the wildcard string ".*").
OR
3. Ask the MDM administrator to display the "Signature Blacklist" setting in the "Android Applications" rule.
4. Verify the setting is configured to include all digital signatures (specified by the wildcard string ".*").

If the MDM console "Package Name Blacklist" or "Signature Blacklist" settings are not set to include all entries, this is a finding.'
  desc 'fix', %q(Configure the Samsung Android 7 with Knox to Blacklist Application Install.

On the MDM console, do one of the following:
1. Add all package names by wildcard ('.*') to the "Package Name Blacklist" setting in the "Android Applications" rule.
2. Add all digital signatures by wildcard ('.*') to the "Signature Blacklist" setting in the "Android Applications" rule.)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76245r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76577'
  tag rid: 'SV-91273r1_rule'
  tag stig_id: 'KNOX-07-012500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
