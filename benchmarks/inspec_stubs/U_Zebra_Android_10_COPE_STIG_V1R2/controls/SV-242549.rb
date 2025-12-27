control 'SV-242549' do
  title 'Zebra Android 10 must be configured to disable exceptions to the access control policy that prevents application processes from accessing all data stored by other application processes.'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review documentation on the Zebra Android 10 device and inspect the configuration on the Zebra Android 10 device to verify the access control policy that prevents [selection: application processes] from accessing [selection: all] data stored by other [selection: application processes] is enabled.

This validation procedure is performed only on the MDM Administration Console. 

On the MDM console:
1. Open User restrictions.
2. Select "Disallow cross profile copy/paste".
3. Select "Disallow sharing data into the profile".

If the MDM console device policy is not set to disable data sharing between profiles, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to enable the access control policy that prevents [selection: application processes, groups of application processes] from accessing [selection: all, private] data stored by other [selection: application processes, groups of application processes].

Note: All application data is inherently sandboxed and isolated from other applications. 

To disable copy/paste on the MDM console:
1. Open User restrictions.
2. Select "Disallow cross profile copy/paste".
3. Select "Disallow sharing data into the profile".'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45824r714490_chk'
  tag severity: 'medium'
  tag gid: 'V-242549'
  tag rid: 'SV-242549r852819_rule'
  tag stig_id: 'ZEBR-10-004500'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-45781r714491_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
