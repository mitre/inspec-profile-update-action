control 'SV-221240' do
  title 'The Exchange Spam Evaluation filter must be enabled.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages may be eliminated from the transport message stream, preventing their entry into the Exchange environment. This significantly reduces the attack vector for inbound email-borne spam and malware.

Spam Evaluation filters scan inbound email messages for evidence of spam and other attacks that primarily use "social engineering" techniques. Upon evaluation completion, a rating is assigned to each message estimating the likelihood of its being spam. Upon arrival at the destination mailbox, the junk mail filter threshold (also configurable) determines whether the message will be withheld from delivery, delivered to the junk mail folder, or delivered to the user’s inbox.'
  desc 'check', 'Note: If third-party anti-spam product is being used, the anti-spam product must be configured to meet the requirement.

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Select Name, Identity, Enabled

If the value of "Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ContentFilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22955r411846_chk'
  tag severity: 'medium'
  tag gid: 'V-221240'
  tag rid: 'SV-221240r612603_rule'
  tag stig_id: 'EX16-ED-000410'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22944r411847_fix'
  tag 'documentable'
  tag legacy: ['SV-95271', 'V-80561']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
