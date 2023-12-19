control 'SV-221242' do
  title 'Exchange messages with a malformed From address must be rejected.'
  desc 'Sender Identification (SID) is an email antispam sanitization process. Sender ID uses DNS MX record lookups to verify the Simple Mail Transfer Protocol (SMTP) sending server is authorized to send email for the originating domain.
 
Failure to implement Sender ID risks that spam could be admitted into the email domain that originates from rogue servers. Most spam content originates from domains where the IP address has been spoofed prior to sending, thereby avoiding detection. For example, messages with malformed or incorrect "purported responsible sender" data in the message header could be (best case) created by using RFI noncompliant software but is more likely to be spam.'
  desc 'check', 'Note: If third-party anti-spam product is being used, the anti-spam product must be configured to meet the requirement.

Open the Exchange Management Shell and enter the following command:

Get-SenderIdConfig | Select Name, Identity, SpoofedDomainAction

If the value of "SpoofedDomainAction" is not set to "Reject", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderIdConfig -SpoofedDomainAction Reject'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22957r411852_chk'
  tag severity: 'medium'
  tag gid: 'V-221242'
  tag rid: 'SV-221242r612603_rule'
  tag stig_id: 'EX16-ED-000430'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22946r411853_fix'
  tag 'documentable'
  tag legacy: ['SV-95275', 'V-80565']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
