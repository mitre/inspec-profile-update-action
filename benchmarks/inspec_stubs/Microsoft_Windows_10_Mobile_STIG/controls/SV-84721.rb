control 'SV-84721' do
  title 'Windows 10 Mobile must be configured to disable automatic updates of system software.'
  desc 'FOTA allows the user to download and install firmware updates over-the-air. These updates can include OS upgrades, security patches, bug fixes, new features and applications. Since the updates are controlled by the carriers, DoD will not have an opportunity to review and update policies prior to update availability to end users. Disabling FOTA will mitigate the risk of allowing users access to applications that could compromise DoD sensitive data. After reviewing the update and adjusting any necessary policies (i.e., disabling applications determined to pose risk), the administrator can re-enable FOTA.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review Windows 10 Mobile documentation and inspect the configuration on Windows 10 Mobile to disable automatic updates of system software.

This validation procedure is performed only on the MDM administration console.

On the MDM administration console:

1. Ask the MDM administrator to verify the OS Upgrade compliance policies.
2. Find the settings for managing Windows OS updates.
3. Verify the "Update/AllowAutoUpdate" policy is set to a value of "1 - Auto install the update and then notify the user to schedule a device restart." and the "Update/BranchReadinessLevel" policy is set to a value of "32 – User gets upgrades from Current Branch for Business (CBB)".

If the MDM does not have a compliance policy that sets the value of "Update/AllowAutoUpdate" to "1 - Auto install the update and then notify the user to schedule a device restart" and the value of "Update/RequireDeferUpgrade" to "32 – User gets upgrades from Current Branch for Business (CBB)", this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a policy which configures the "Update/AllowAutoUpdate" and "Update/BranchReadinessLevel" policies.

Update/AllowAutoUpdate controls how automatic OS upgrades are deployed and should be set to a value of "1 - Auto install the update and then notify the user to schedule a device restart." and Update/BranchReadinessLevel which enables upgrades to be deferred until the Semi-Annual Channel/Broad Deployment releases are available.  This needs to be set to a value of "32 – User gets upgrades from Current Branch for Business (CBB)".

Deploy the MDM policy to managed devices. 

Note: These policies require that phones are upgraded to Windows 10 Mobile Enterprise.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70575r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70099'
  tag rid: 'SV-84721r2_rule'
  tag stig_id: 'MSWM-10-201901'
  tag gtitle: 'PP-MDF-201031'
  tag fix_id: 'F-76335r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
