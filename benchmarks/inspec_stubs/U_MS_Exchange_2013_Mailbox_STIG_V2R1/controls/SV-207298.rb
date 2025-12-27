control 'SV-207298' do
  title 'Exchange Mail Quota settings must not restrict receiving mail.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded. Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable. There are multiple controls, which supply graduated levels of opportunity to respond before risking email service loss. 

This control prohibits the user from sending an email when the mailbox limit reaches the prohibit send quota value.

Note: Best practice for this setting is to prohibit the user from sending email when the mailbox reaches 90 percent of capacity.'
  desc 'check', "Review the Email Domain Security Plan (EDSP). 

Determine the value for Prohibit Send Quota Limit.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, ProhibitSendQuota

If the value of ProhibitSendQuota is not set to the site's Prohibit Send Quota Limit, this is a finding."
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase  -Identity <'IdentityName'> -ProhibitSendQuota <'QuotaLimit'>

Note: The <IdentityName> and <QuotaLimit> values must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7556r393407_chk'
  tag severity: 'low'
  tag gid: 'V-207298'
  tag rid: 'SV-207298r615936_rule'
  tag stig_id: 'EX13-MB-000160'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-7556r393408_fix'
  tag 'documentable'
  tag legacy: ['SV-84625', 'V-70003']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
