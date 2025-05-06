control 'SV-43976' do
  title 'Sender Identification Framework must be enabled.'
  desc 'Email is only as secure as the recipient. When the recipient is an email server accepting inbound messages, authenticating the sender enables the receiver to better assess message quality and to validate the sending domain as authentic. One or more authentication techniques used in combination can be effective in reducing SPAM, PHISHING, and FORGERY attacks. 

The Sender ID Framework (SIDF) receiver accesses specially formatted DNS records (SPF format) that contain the IP address of authorized sending servers for the sending domain that can be compared to data in the email message header. Receivers are able to validate the authenticity of the sending domain, helping to avoid receiving inbound messages from PHISHING or other SPAM domains.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-SenderIdConfig | Select Name, Identity, Enabled

If the value of 'Enabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderIdConfig -Enable $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41662r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33556'
  tag rid: 'SV-43976r1_rule'
  tag stig_id: 'Exch-2-334'
  tag gtitle: 'Exch-2-334'
  tag fix_id: 'F-37448r1_fix'
  tag 'documentable'
end
