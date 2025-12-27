control 'SV-44058' do
  title 'Sender reputation filter must identify SPAM block level.'
  desc 'By performing filtering at the perimeter, up to 90% of SPAM, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment.  Sender reputation is anti-SPAM functionality that blocks messages according to many characteristics of the sender. Sender reputation relies on persisted data about the sender to determine what action, if any, to take on an inbound message. This setting enables the threshold at which an email will be considered SPAM.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:
 
Get-SenderReputationConfig | Select SrlBlockThreshold

If the value of 'SrlBlockThreshold' is not set to '6', this is a finding.

If the value of 'SrlBlockThreshold' is set to a value other than 6 and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderReputationConfig -SrlBlockThreshold 6.

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41747r3_chk'
  tag severity: 'medium'
  tag gid: 'V-33638'
  tag rid: 'SV-44058r1_rule'
  tag stig_id: 'Exch-2-324'
  tag gtitle: 'Exch-2-324'
  tag fix_id: 'F-37530r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
