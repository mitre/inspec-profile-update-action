control 'SV-228734' do
  title 'The mobile operating system must be configured to enforce an application installation policy by specifying one or more authorized application repositories, including [selection: DoD-approved commercial app repository, MDM server, mobile application store].'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications.

SFR ID: FMT_SMF_EXT.1.1 #8a'
  desc 'check', 'Review configuration settings to confirm "Allow Trusting New Enterprise App Authors" restriction is disabled.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify the "Allow Trusting New Enterprise App Authors" is disabled.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Trusting enterprise apps not allowed" is listed.

If the "Allow Trusting New Enterprise App Authors" is not disabled in the iOS/iPadOS management tool or on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Allow Trusting New Enterprise App Authors".'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30969r509830_chk'
  tag severity: 'medium'
  tag gid: 'V-228734'
  tag rid: 'SV-228734r852627_rule'
  tag stig_id: 'AIOS-14-000700'
  tag gtitle: 'PP-MDF-301080'
  tag fix_id: 'F-30946r509831_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
