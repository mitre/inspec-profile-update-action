control 'SV-44011' do
  title 'Mail quota settings must not restrict receiving mail.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded.   Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable.   

Failure to allow mail receipt may impede users from receiving mission critical data.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, ProhibitSendReceiveQuota

If the value of 'ProhibitSendReceiveQuota' is set to an alternate value, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of 'ProhibitSendReceiveQuota' is not set to 'Unlimited', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase <'MailboxDatabaseName'> -ProhibitSendReceiveQuota 'Unlimited'

If an alternate value is desired from ProhibitSendReceiveQuota, obtain signoff with risk acceptance and document in the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41698r2_chk'
  tag severity: 'low'
  tag gid: 'V-33591'
  tag rid: 'SV-44011r2_rule'
  tag stig_id: 'Exch-1-301'
  tag gtitle: 'Exch-1-301'
  tag fix_id: 'F-37483r2_fix'
  tag 'documentable'
end
