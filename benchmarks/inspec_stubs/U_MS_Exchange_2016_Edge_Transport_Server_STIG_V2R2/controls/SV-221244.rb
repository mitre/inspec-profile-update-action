control 'SV-221244' do
  title 'The Exchange tarpitting interval must be set.'
  desc 'Tarpitting is the practice of artificially delaying server responses for specific Simple Mail Transfer Protocol (SMTP) communication patterns that indicate high volumes of spam or other unwelcome messages. The intent of tarpitting is to slow down the communication process for spam batches to reduce the cost effectiveness of sending spam and thwart directory harvest attacks.  

A directory harvest attack is an attempt to collect valid email addresses from a particular organization so the email addresses can be added to a spam database. A program can be written to collect email addresses that return a "Recipient OK" SMTP response and discard all email addresses that return a "User unknown" SMTP response.

Tarpitting makes directory harvest attacks too costly to automate efficiently.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, TarpitInterval

For each Receive connector, if the value of "TarpitInterval" is not set to "00:00:05" or greater, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -TarpitInterval '00:00:05'

Note: The <IdentityName> value and the Interval must be in single quotes.

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22959r411858_chk'
  tag severity: 'medium'
  tag gid: 'V-221244'
  tag rid: 'SV-221244r612603_rule'
  tag stig_id: 'EX16-ED-000480'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22948r411859_fix'
  tag 'documentable'
  tag legacy: ['SV-95279', 'V-80569']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
