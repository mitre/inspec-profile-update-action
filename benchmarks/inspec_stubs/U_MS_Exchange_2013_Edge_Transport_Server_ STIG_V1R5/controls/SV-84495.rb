control 'SV-84495' do
  title 'The Exchange Sender Reputation filter must identify the spam block level.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. Sender Reputation is antispam functionality that blocks messages according to many characteristics of the sender. Sender Reputation relies on persisted data about the sender to determine what action, if any, to take on an inbound message. This setting enables the threshold at which an email will be considered spam.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:
 
Get-SenderReputationConfig | Select Name, SrlBlockThreshold

If the value of SrlBlockThreshold is not set to 6, this is a finding.

or

If the value of SrlBlockThreshold is set to a value other than 6 and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderReputationConfig -SrlBlockThreshold 6

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70341r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69873'
  tag rid: 'SV-84495r1_rule'
  tag stig_id: 'EX13-EG-000195'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
