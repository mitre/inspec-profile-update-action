control 'SV-207299' do
  title 'The Exchange Mail Store storage quota must issue a warning.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded. Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable. There are multiple controls, which supply graduated levels of opportunity to respond before risking data loss. 

This control sends the user a warning message that the mailbox is reaching its limit. The user at this point can still send and receive email.
 
Note: Best practice is to send this warning when the mailbox reaches 75 percent of capacity.'
  desc 'check', "Review the Email Domain Security Plan (EDSP). 

Determine the value for Issue Warning Quota.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, IssueWarningQuota

If the value of IssueWarningQuota is not set to the site's Issue Warning Quota, this is a finding."
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase  -Identity  <'IdentityName'> -IssueWarningQuota <'WarningQuota'>

Note: The <IdentityName> and <WarningQuota> values must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7557r393410_chk'
  tag severity: 'low'
  tag gid: 'V-207299'
  tag rid: 'SV-207299r615936_rule'
  tag stig_id: 'EX13-MB-000165'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-7557r393411_fix'
  tag 'documentable'
  tag legacy: ['SV-84627', 'V-70005']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
