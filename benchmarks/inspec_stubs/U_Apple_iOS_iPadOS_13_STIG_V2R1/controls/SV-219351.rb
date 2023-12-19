control 'SV-219351' do
  title 'Apple iOS/iPadOS must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: Apple App Store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review configuration settings to confirm "Allow Trusting New Enterprise App Authors" restriction is disabled.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify the "Allow Trusting New Enterprise App Authors" is disabled.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Trusting enterprise apps not allowed" is listed.

If the "Allow Trusting New Enterprise App Authors" is not disabled in the iOS/iPadOS management tool or on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Allow Trusting New Enterprise App Authors".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21076r547570_chk'
  tag severity: 'medium'
  tag gid: 'V-219351'
  tag rid: 'SV-219351r604137_rule'
  tag stig_id: 'AIOS-13-001000'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-21075r547571_fix'
  tag 'documentable'
  tag legacy: ['SV-106533', 'V-97429']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
