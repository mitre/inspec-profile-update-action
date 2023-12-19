control 'SV-207297' do
  title 'Exchange Mail quota settings must not restrict receiving mail.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded. Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable.  

Failure to allow mail receipt may impede users from receiving mission-critical data.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, ProhibitSendReceiveQuota

If the value of ProhibitSendReceiveQuota is not set to Unlimited, this is a finding.

or

If the value of ProhibitSendReceiveQuote is set to an alternate value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'IdentityName'> -ProhibitSendReceiveQuota Unlimited

Note: The <IdentityName> value must be in quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7555r393404_chk'
  tag severity: 'low'
  tag gid: 'V-207297'
  tag rid: 'SV-207297r615936_rule'
  tag stig_id: 'EX13-MB-000155'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-7555r393405_fix'
  tag 'documentable'
  tag legacy: ['SV-84623', 'V-70001']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
