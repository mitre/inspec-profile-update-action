control 'SV-237426' do
  title 'The Microsoft SCOM Agent Action Account must be a local system account.'
  desc 'The SCOM agent action account is the account agent used to perform tasks on an individual machine. By default, the action agent account is the local system account, but this can be configured to run as a service account. In that scenario, the account will be running locally in memory and could be used by an attacker to laterally move throughout an environment. Using the local system account limits the ability to laterally traverse within the environment if a specific endpoint is compromised.'
  desc 'check', 'From the SCOM console, go to the administration workspace. 

Under Run As Configuration, select Profiles.

Double-click on the Default Action Account in the center pane. From the box that appears, select the Run As accounts link.

Under the Account Name column, verify that ONLY management servers are running with a specified user account. All other accounts should say Local System Action Account.

If any non-management servers have a specific user account listed, this is a finding.

Elevate to a CAT I if the specified account is a local administrator on other systems. This can be downgraded to CAT III if the agent action account has been restricted from logging on to all other systems except the monitored endpoint, as the risk of credential leakage has been sufficiently mitigated.'
  desc 'fix', 'From the SCOM console, go to the administration workspace. Under Run As Configuration, select Profiles.

Double-click on the Default Action Account in the center pane. From the box that appears, select the Run As accounts link.

Click on each non-management server that is configured with a Run As account and click Edit. From the box that appears, select "Local System Account" in the Run As account drop down. Click OK. 

Click Save once finished with all systems.'
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40645r643922_chk'
  tag severity: 'medium'
  tag gid: 'V-237426'
  tag rid: 'SV-237426r643924_rule'
  tag stig_id: 'SCOM-AC-000004'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40608r643923_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
