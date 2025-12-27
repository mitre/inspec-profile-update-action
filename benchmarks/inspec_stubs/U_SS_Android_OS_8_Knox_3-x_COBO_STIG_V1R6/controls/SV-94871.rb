control 'SV-94871' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure application install blacklist.'
  desc 'Blacklisting all applications is required so that only whitelisted applications can be installed on the device. Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist and blacklist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to Blacklist Application Install. 

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, perform Steps 1 and 2 or Steps 3 and 4:
1. Ask the MDM Administrator to display the "Package Name Blacklist" setting in the "Android Applications" rule.
2. Verify the setting is configured to include all package names (specified by the wildcard string ".*").
3. Ask the MDM Administrator to display the "Signature Blacklist" setting in the "Android Applications" rule.
4. Verify the setting is configured to include all digital signatures (specified by the wildcard string ".*").

If the MDM console "Package Name Blacklist" or "Signature Blacklist" settings are not set to include all entries, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to Blacklist Application Install.

On the MDM console, do one of the following:
1. Add all package names by wildcard (".*") to the "Package Name Blacklist" setting in the "Android Applications" rule.
2. Add all digital signatures by wildcard (".*") to the "Signature Blacklist" setting in the "Android Applications" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80167'
  tag rid: 'SV-94871r1_rule'
  tag stig_id: 'KNOX-08-001000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-86973r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
