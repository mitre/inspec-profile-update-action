control 'SV-44062' do
  title 'Filtered messages must be archived.'
  desc 'By performing filtering at the perimeter, up to 90% of SPAM, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. This significantly reduces the attack vector for inbound Email-borne SPAM and malware. 

As messages are filtered, it is prudent to temporarily host them in an archive for evaluation by administrators or users. The archive can be used to recover messages that might have been inappropriately filtered, preventing data loss, and to provide a base of analysis that can provide future filter refinements.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Select QuarantineMailbox

If no SMTP address is assigned to 'QuarantineMailbox', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ContentFilterConfig  -QuarantineMailbox <'SmtpAddressOfMailbox'>"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41752r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33642'
  tag rid: 'SV-44062r1_rule'
  tag stig_id: 'Exch-2-308'
  tag gtitle: 'Exch-2-308'
  tag fix_id: 'F-37535r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
