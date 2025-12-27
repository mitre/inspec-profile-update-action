control 'SV-255218' do
  title 'Microsoft Android 11 must be configured to disable exceptions to the access control policy that prevent application processes from accessing all data stored by other application processes.'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DOD sensitive information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review documentation on the Microsoft Android device and inspect the configuration on the Microsoft Android device to verify the access control policy that prevents [selection: application processes] from accessing [selection: all] data stored by other [selection: application processes] is enabled.

This validation procedure is performed only on the EMM Administration console. 

On the EMM console:
1. Open "Set user restrictions".
2. Verify that "Disallow cross profile copy/paste" is toggled to "On".
3. Verify that "Disallow sharing data into the profile" is toggled to "On".

If the EMM console device policy is not set to disable data sharing between profiles, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to enable the access control policy that prevents [selection: application processes, groups of application processes] from accessing [selection: all, private] data stored by other [selection: application processes, groups of application processes].

Note: All application data is inherently sandboxed and isolated from other applications. 

To disable copy/paste on the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disallow cross profile copy/paste" to "On".
3. Toggle "Disallow sharing data into the profile" to "On".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58831r870754_chk'
  tag severity: 'medium'
  tag gid: 'V-255218'
  tag rid: 'SV-255218r870756_rule'
  tag stig_id: 'MSFT-11-004500'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-58775r870755_fix'
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002530']
  tag nist: ['AC-6 (8)', 'SC-39']
end
