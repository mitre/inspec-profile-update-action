control 'SV-257112' do
  title 'Apple iOS/iPadOS 16 must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DOD-approved commercial app repository, MDM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DOD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review configuration settings to confirm "Allow Trusting New Enterprise App Authors" is disabled.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify "Allow Trusting New Enterprise App Authors" is disabled.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Trusting enterprise apps not allowed" is listed.

If "Allow Trusting New Enterprise App Authors" is not disabled in the iOS/iPadOS management tool or on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Allow Trusting New Enterprise App Authors".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60797r904234_chk'
  tag severity: 'medium'
  tag gid: 'V-257112'
  tag rid: 'SV-257112r904236_rule'
  tag stig_id: 'AIOS-16-707000'
  tag gtitle: 'PP-MDF-333050'
  tag fix_id: 'F-60738r904235_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
