control 'SV-207322' do
  title 'The Exchange Public Store storage quota must be limited.'
  desc 'This setting controls the maximum sizes of a public folder and the system’s response if these limits are exceeded. There are two available controls and the system response when the quota has been exceeded. 

The first control sends an email warning to Folder Owners roles, alerting them that the folder has exceeded its quota. The second level prevents posting any additional items to the folder.  

As a practical matter, Level 1 serves the purpose of prompting owners to manage their folders. Level 2 impedes users in their ability to work and is not required where folder use interruption is not acceptable. Public Folder Storage Quota Limitations are not a substitute for overall disk space monitoring.'
  desc 'check', 'If public folders are not used, this check is not applicable.

Review the Email Domain Security Plan (EDSP). 

Determine the value for ProhibitPostQuota.

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase | Select Name, Identity, ProhibitPostQuota

If the value of ProhibitPostQuota is not set to the ProhibitPostQuota values documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command: 

Set-PublicFolderDatabase -Identity <'IdentityName'> -ProhibitPostQuota <'QuotaLimit'>

Note: The <IdentityName> and <QuotaLimit> values must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7580r393479_chk'
  tag severity: 'low'
  tag gid: 'V-207322'
  tag rid: 'SV-207322r615936_rule'
  tag stig_id: 'EX13-MB-000280'
  tag gtitle: 'SRG-APP-000367'
  tag fix_id: 'F-7580r393480_fix'
  tag 'documentable'
  tag legacy: ['SV-84673', 'V-70051']
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end
