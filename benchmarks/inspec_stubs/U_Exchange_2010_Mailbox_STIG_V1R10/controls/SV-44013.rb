control 'SV-44013' do
  title 'Mail Store storage quota must limit send.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded.   Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable.   There are multiple controls, which supply graduated levels of opportunity to respond before risking email service loss.  

This control prohibits the user from sending an email when the mailbox limit reaches the prohibit send quota value.

Note: Best practice for this setting is to prohibit the user from sending email when the mailbox reaches 90 percent of capacity.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the value for 'Prohibit Send Quota Limit'.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, ProhibitSendQuota

If the value of 'ProhibitSendQuota' is not set to the sites 'ProhibitSendQuotaLimit', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase <'MailboxDatabaseName'> -ProhibitSendQuota <'SitesProhibitSendQuotaLimit'>"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41700r1_chk'
  tag severity: 'low'
  tag gid: 'V-33593'
  tag rid: 'SV-44013r1_rule'
  tag stig_id: 'Exch-1-303'
  tag gtitle: 'Exch-1-303'
  tag fix_id: 'F-37485r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
