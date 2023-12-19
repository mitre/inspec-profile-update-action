control 'SV-228379' do
  title 'Exchange Mail quota settings must not restrict receiving mail.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded. Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable.

Failure to allow mail receipt may impede users from receiving mission-critical data.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, ProhibitSendReceiveQuota

If the value of "ProhibitSendReceiveQuota" is not set to "Unlimited", this is a finding.

or

If the value of "ProhibitSendReceiveQuota" is set to an alternate value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'IdentityName'> -ProhibitSendReceiveQuota Unlimited

Note: The <IdentityName> value must be in single quotes.

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30612r496933_chk'
  tag severity: 'low'
  tag gid: 'V-228379'
  tag rid: 'SV-228379r879650_rule'
  tag stig_id: 'EX16-MB-000310'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-30597r496934_fix'
  tag 'documentable'
  tag legacy: ['SV-95383', 'V-80673']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
