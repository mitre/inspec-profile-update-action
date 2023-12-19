control 'SV-77327' do
  title 'Riverbed Optimization System (RiOS) must disable the local Shark and Monitor accounts so they cannot be used as shared accounts by users.'
  desc "The Monitor and Shark accounts which are default group accounts with shared credentials. Monitor and Shark accounts are not enabled by default, but cannot be deleted since these network tools are designed to look for that account. Monitor is a read-only account for auditor's configuration management. Shark is used to access packet captures. If the credentials for these accounts are changed, the function of the system will not be adversely impacted."
  desc 'check', 'Verify that RiOS is configured to the assigned privilege level for each administrator.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Verify the privilege level values for Shark and Monitor

If all privileges for the Shark and Monitor accounts are not set to Deny, this is a finding.'
  desc 'fix', 'Configure RiOS to enforce assigned privilege level for each administrator in accordance with site documented requirements.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Remove all values of "Roles and Permissions" for the Monitor and Shark accounts

Click "Apply" to save the changes
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62837'
  tag rid: 'SV-77327r1_rule'
  tag stig_id: 'RICX-DM-000003'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-68755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
