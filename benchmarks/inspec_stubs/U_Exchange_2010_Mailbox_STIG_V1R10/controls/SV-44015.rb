control 'SV-44015' do
  title 'Mail Store storage quota must issue a warning.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded.   Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable.   There are multiple controls, which supply graduated levels of opportunity to respond before risking data loss.  

This control sends the user a warning message that the mailbox is reaching its limit. The user at this point can still send and receive email.
  
Note: Best practice is to send this warning when the mailbox reaches 75 percent of capacity.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP)  and locate the value for 'IssueWarningQuota'.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, IssueWarningQuota

If the value of 'IssueWarningQuota' is not set to the sites 'Issue Warning Quota', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase <'MailboxDatabaseName'> -IssueWarningQuota <'SitesIssueWarningQuota'>"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41702r1_chk'
  tag severity: 'low'
  tag gid: 'V-33595'
  tag rid: 'SV-44015r1_rule'
  tag stig_id: 'Exch-1-306'
  tag gtitle: 'Exch-1-306'
  tag fix_id: 'F-37487r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
