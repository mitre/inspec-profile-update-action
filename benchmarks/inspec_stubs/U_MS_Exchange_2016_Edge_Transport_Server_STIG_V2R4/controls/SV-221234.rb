control 'SV-221234' do
  title 'Exchange filtered messages must be archived.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. This significantly reduces the attack vector for inbound email-borne spam and malware. 

As messages are filtered, it is prudent to temporarily host them in an archive for evaluation by administrators or users. The archive can be used to recover messages that might have been inappropriately filtered, preventing data loss, and to provide a base of analysis that can provide future filter refinements.'
  desc 'check', 'Note: If third-party anti-spam product is being used, the anti-spam product must be configured to meet the requirement.

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Select Name, QuarantineMailbox

If no SMTP address is assigned to "QuarantineMailbox", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ContentFilterConfig -QuarantineMailbox <'QuarantineMailbox SmtpAddress'>

Note: The <QuarantineMailbox SmtpAddress> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22949r411828_chk'
  tag severity: 'medium'
  tag gid: 'V-221234'
  tag rid: 'SV-221234r612603_rule'
  tag stig_id: 'EX16-ED-000350'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22938r411829_fix'
  tag 'documentable'
  tag legacy: ['SV-95259', 'V-80549']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
