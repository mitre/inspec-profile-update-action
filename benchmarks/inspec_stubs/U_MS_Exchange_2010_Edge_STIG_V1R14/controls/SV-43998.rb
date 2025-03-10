control 'SV-43998' do
  title 'Tarpitting interval must be set.'
  desc "Tarpitting is the practice of artificially delaying server responses for specific SMTP communication patterns that indicate high volumes of SPAM or other unwelcome messages. The intent of tarpitting is to slow down the communication process for SPAM batches so that the cost effectiveness of sending SPAM is reduced and directory harvest attacks may be thwarted.  

A directory harvest attack is an attempt to collect valid email addresses from a particular organization so that the email addresses can be added to a spam database.  A program can be written to collect email addresses that return a 'Recipient OK' SMTP response and discards all email addresses that return a 'User unknown' SMTP response.  

Tarpitting makes directory harvest attacks too costly to automate efficiently."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, TarpitInterval

If the value of 'TarpitInterval' is not set to 00:00:05 or greater, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -TarpitInterval 00:00:05"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41683r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33578'
  tag rid: 'SV-43998r1_rule'
  tag stig_id: 'Exch-2-739'
  tag gtitle: 'Exch-2-739'
  tag fix_id: 'F-37469r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
