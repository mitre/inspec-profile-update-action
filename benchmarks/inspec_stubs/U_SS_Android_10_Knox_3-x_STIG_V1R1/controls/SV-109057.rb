control 'SV-109057' do
  title 'Samsung Android Work Environment must be configured to disable exceptions to the access control policy that prevents application processes, groups of application processes from accessing all, private data stored by other application processes, groups of application processes. - Disable Move files to personal'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. Data sharing restrictions mitigate this risk. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the access control policy prevents groups of application processes from accessing all data stored by other groups of application processes.

This procedure is for verifying that the moving of files to the Personal Environment is disabled and is applicable only to COPE only.

This procedure is performed on the management tool Administration console only.

This configuration is the default configuration. If the management tool does not provide the capability to configure "Move files to personal", there is NO finding because the default setting cannot be changed.

On the management tool, in the Work Environment KPE RCP section, verify "Move files to personal" is set to "Disallow".

If the management tool provides the capability to configure the "Move files to personal" policy and it is not set to "Disallow", this is a finding.

If the management tool does not provide the capability to configure the policy, this requirement is inherently met and there is NO finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to enable the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes.

This guidance is for disabling the moving of files to the Personal Environment and is applicable to COPE only.

The configuration of "Move files to personal" is the default required configuration. No configuration is required.

On the management tool, in the device restrictions section, set "Move files to personal" to "Disallow".

Note: "Move files to workspace" may be configured if there is a DoD mission need for this feature.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99953'
  tag rid: 'SV-109057r1_rule'
  tag stig_id: 'KNOX-10-004600'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-105637r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
