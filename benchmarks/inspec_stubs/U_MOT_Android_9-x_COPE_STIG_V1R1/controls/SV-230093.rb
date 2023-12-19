control 'SV-230093' do
  title 'The Motorola Android Pie must be configured to disable exceptions to the access control policy that prevents application processes from accessing all data stored by other application processes.'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review documentation on the Motorola Android device and inspect the configuration on the Motorola Android device to verify the access control policy that prevents [selection: application processes] from accessing [selection: all] data stored by other [selection: application processes] is enabled.

This validation procedure is performed only on the MDM Administration Console. 

On the MDM console: 
1. Open Restrictions settings.
2. Open User Restrictions.
3. Verify "Disallow cross profile copy/paste" is selected.
4. Verify "Disallow sharing data into the profile" is selected.

If the MDM console device policy is not set to disable data sharing between profiles, this is a finding.'
  desc 'fix', 'Configure the Motorola Android Pie to enable the access control policy that prevents [selection: application processes, groups of application processes] from accessing [selection: all, private] data stored by other [selection: application processes, groups of application processes].

NOTE: All application data is inherently sandboxed and isolated from other applications. 

To disable copy/paste on the MDM console: 
1. Open Restrictions settings.
2. Open User Restrictions.
3. Select "Disallow cross profile copy/paste".
4. Select "Disallow sharing data into the profile".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32408r538275_chk'
  tag severity: 'medium'
  tag gid: 'V-230093'
  tag rid: 'SV-230093r569708_rule'
  tag stig_id: 'MOTO-09-004500'
  tag gtitle: 'GOOG-09-004500'
  tag fix_id: 'F-32386r538276_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
