control 'SV-228380' do
  title 'Exchange Mail Quota settings must not restrict receiving mail.'
  desc 'Mail quota settings control the maximum sizes of a user’s mailbox and the system’s response if these limits are exceeded. Mailbox data that is not monitored against a quota increases the risk of mail loss due to filled disk space, which can also render the system unavailable. Multiple controls supply graduated levels of opportunity to respond before risking email service loss. 

This control prohibits the user from sending an email when the mailbox limit reaches the prohibit send quota value.

Note: Best practice for this setting is to prohibit the user from sending email when the mailbox reaches 90 percent of capacity.'
  desc 'check', %q(Review the Email Domain Security Plan (EDSP) or document that contains this information. 

Determine the value for the Prohibit Send Quota limit.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, ProhibitSendQuota

If the value of "ProhibitSendQuota" is not set to the site's Prohibit Send Quota limit, this is a finding.)
  desc 'fix', "Update the EDSP to specify the value for the Prohibit Send Quota limit or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase  -Identity <'IdentityName'> -ProhibitSendQuota <'QuotaLimit'>

Note: The <IdentityName> and <QuotaLimit> values must be in single quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30613r496936_chk'
  tag severity: 'low'
  tag gid: 'V-228380'
  tag rid: 'SV-228380r879650_rule'
  tag stig_id: 'EX16-MB-000320'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-30598r496937_fix'
  tag 'documentable'
  tag legacy: ['SV-95385', 'V-80675']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
