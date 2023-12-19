control 'SV-84487' do
  title 'Exchange filtered messages must be archived.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. This significantly reduces the attack vector for inbound email-borne spam and malware. 

As messages are filtered, it is prudent to temporarily host them in an archive for evaluation by administrators or users. The archive can be used to recover messages that might have been inappropriately filtered, preventing data loss, and to provide a base of analysis that can provide future filter refinements.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Select Name, QuarantineMailbox

If no SMTP address is assigned to QuarantineMailbox, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ContentFilterConfig -QuarantineMailbox <'QuarantineMailbox SmtpAddress'>

Note: The <QuarantineMailbox SmtpAddress> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69865'
  tag rid: 'SV-84487r1_rule'
  tag stig_id: 'EX13-EG-000175'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
