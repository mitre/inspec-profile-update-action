control 'SV-44063' do
  title 'Messages with blank sender field must be filtered.'
  desc 'By performing filtering at the perimeter, up to 90% of SPAM, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment.  Anonymous email (messages with blank sender fields) cannot be replied to.   Messages formatted in this way may be attempting to hide their true origin to avoid responses, or to SPAM any receiver with impunity while hiding their source of origination.  

Rather than spend resource and risk infection while evaluating them, it is recommended that these messages be filtered immediately upon receipt and not forwarded to end users.'
  desc 'check', "This requirement is N/A for SIPR enclaves. 

This requirement is N/A if the organization subscribes to EEMSG or other similar DoD enterprise protections for email services.

Open the Exchange Management Shell and enter the following command:

Get-SenderFilterConfig | Select BlankSenderBlockingEnabled

If the value of 'BlankSenderBlockingEnabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderFilterConfig -BlankSenderBlockingEnabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41753r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33643'
  tag rid: 'SV-44063r2_rule'
  tag stig_id: 'Exch-2-314'
  tag gtitle: 'Exch-2-314'
  tag fix_id: 'F-37536r1_fix'
  tag 'documentable'
end
