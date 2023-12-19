control 'SV-44051' do
  title 'Messages with malformed from address must be rejected.'
  desc "Sender Identification (SID) is an email anti-spam sanitization process.  Sender ID uses DNS MX record lookups to verify the SMTP sending server is authorized to send email for the originating domain.
 
Failure to implement Sender ID risks that SPAM could be admitted into the email domain that originates from rogue servers.  Most SPAM content originates from domains where the IP address has been spoofed prior to sending, thereby avoiding detection.   For example, messages with malformed or incorrect 'purported responsible sender' data in the message header could be (best case) created by using RFI non-compliant software, but is more likely to be SPAM."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-SenderIdConfig | Select Name, Identity, SpoofedDomainAction

If the value of 'SpoofedDomainAction' is not set to 'Reject', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderIdConfig -SpoofedDomainAction Reject'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41740r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33631'
  tag rid: 'SV-44051r1_rule'
  tag stig_id: 'Exch-2-333'
  tag gtitle: 'Exch-2-333'
  tag fix_id: 'F-37523r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
