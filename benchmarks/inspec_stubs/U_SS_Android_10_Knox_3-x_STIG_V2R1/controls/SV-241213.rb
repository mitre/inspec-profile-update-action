control 'SV-241213' do
  title 'Samsung Android Work Environment must be configured to disable exceptions to the access control policy that prevents application processes, groups of application processes from accessing all, private data stored by other application processes, groups of application processes. - Disable Copy and Paste data'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. Data sharing restrictions mitigate this risk. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the access control policy prevents groups of application processes from accessing all data stored by other groups of application processes.

This procedure is for verifying that the sharing of clipboard data from the Work Environment to the Personal Environment is disabled and is applicable to COPE only.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: KPE RCP Sync

On the management tool, in the Work Environment KPE RCP section, verify that "Sharing clipboard to personal" is set to "Disallow".

On the Samsung Android device, do the following:
1. Using any Work Environment app, copy text to the clipboard.
2. Using any Personal Environment app, verify that the clipboard text cannot be pasted.

If on the management tool the "Sharing clipboard to personal" is not set to "Disallow", or on the Samsung Android device the clipboard text can be pasted into a Personal Environment app, this is a finding.

****

Method #2: AE Restriction

On the management tool, in the Work Environment restrictions section, set "Cross profile copy/paste" to "Disallow".

On the Samsung Android device, do the following:
1. Using any Work Environment app, copy text to the clipboard.
2. Using any Personal Environment app, verify that the clipboard text cannot be pasted.

If on the management tool "Cross profile copy/paste" is not set to "Disallow", or on the Samsung Android device the clipboard text can be pasted into a Personal Environment app, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to enable the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes.

This guidance is for disabling the sharing of clipboard data from the Work Environment to the Personal Environment and is applicable to COPE only.

Do one of the following:
- Method #1: KPE RCP Sync
- Method #2: AE Restriction

****

Method #1: KPE RCP Sync

On the management tool, in the Work Environment KPE RCP section, set "Sharing clipboard to personal" to "Disallow".

****

Method #2: AE Restriction

On the management tool, in the Work Environment restrictions section, set "Cross profile copy/paste" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44489r680278_chk'
  tag severity: 'medium'
  tag gid: 'V-241213'
  tag rid: 'SV-241213r852773_rule'
  tag stig_id: 'KNOX-10-004700'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-44448r680279_fix'
  tag 'documentable'
  tag legacy: ['SV-109059', 'V-99955']
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
