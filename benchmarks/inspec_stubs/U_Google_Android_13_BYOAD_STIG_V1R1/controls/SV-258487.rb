control 'SV-258487' do
  title 'Google Android 13 must be configured to disable exceptions to the access control policy that prevent [selection: application processes, groups of application processes] from accessing [selection: all, private] data stored by other [selection: application processes, groups of application processes].'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DOD sensitive information. To mitigate this risk, there are data sharing restrictions, primarily from sharing data from personal (unmanaged) apps and work (managed) apps. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review documentation on the managed Google Android 13 device and inspect the configuration on the Google Android device to verify the access control policy that prevents [selection: application processes] from accessing [selection: all] data stored by other [selection: application processes] is enabled.

This validation procedure is performed only on the EMM Administration Console. 

On the EMM console:

1. Open "User restrictions".
2. Open "Set user restrictions".
3. Verify that "Disallow cross profile copy/paste" is toggled to "ON".
4. Verify that "Disallow sharing data into the profile" is toggled to "ON".

If the EMM console device policy is not set to disable data sharing between profiles, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to enable the access control policy that prevents [selection: application processes, groups of application processes] from accessing [selection: all, private] data stored by other [selection: application processes, groups of application processes].

Note: All application data is inherently sandboxed and isolated from other applications. To disable copy/paste on the EMM console:

1. Open "User restrictions".
2. Open "Set user restrictions".
3. Toggle "Disallow cross profile copy/paste" to "ON".
4. Toggle "Disallow sharing data into the profile" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62227r929275_chk'
  tag severity: 'medium'
  tag gid: 'V-258487'
  tag rid: 'SV-258487r929277_rule'
  tag stig_id: 'GOOG-13-708900'
  tag gtitle: 'PP-MDF-333280'
  tag fix_id: 'F-62136r929276_fix'
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002530']
  tag nist: ['AC-6 (8)', 'SC-39']
end
