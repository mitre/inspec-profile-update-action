control 'SV-231033' do
  title 'Samsung Android Work Environment must be configured to disable exceptions to the access control policy that prevents application processes, groups of application processes from accessing all, private data stored by other application processes, groups of application processes.

- Disable Copy and Paste data'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. Data sharing restrictions mitigate this risk. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the access control policy prevents groups of application processes from accessing all data stored by other groups of application processes.

This procedure is for verifying that the sharing of clipboard data from the Work Environment to the Personal Environment is disabled and is applicable to COPE only.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work Environment RCP section, verify that "Sharing clipboard to personal" is set to "Disallow".

On the Samsung Android device: 
1. Using any Work Environment app, copy text to the clipboard.
2. Using any Personal Environment app, verify that the clipboard text cannot be pasted.

If on the management tool the "Sharing clipboard to personal" is not set to "Disallow", or on the Samsung Android device the clipboard text can be pasted into a Personal Environment app, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to enable the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes.

This guidance is for disabling the sharing of clipboard data from the Work Environment to the Personal Environment and is applicable to COPE only.

On the management tool, in the Work Environment RCP section, set "Sharing clipboard to personal" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33963r592713_chk'
  tag severity: 'medium'
  tag gid: 'V-231033'
  tag rid: 'SV-231033r608683_rule'
  tag stig_id: 'KNOX-11-009200'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-33936r592714_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
