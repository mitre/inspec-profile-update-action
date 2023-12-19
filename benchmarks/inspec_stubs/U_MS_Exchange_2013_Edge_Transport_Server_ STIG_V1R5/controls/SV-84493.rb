control 'SV-84493' do
  title 'The Exchange Sender Reputation filter must be enabled.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. Sender Reputation is antispam functionality that blocks messages according to many characteristics of the sender. Sender Reputation relies on persisted data about the sender to determine what action, if any, to take on an inbound message. This setting enables the Sender Reputation function.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:
 
Get-SenderReputationConfig | Select Name, Enabled

If the value of Enabled is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:
 
Set-SenderReputationConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70339r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69871'
  tag rid: 'SV-84493r1_rule'
  tag stig_id: 'EX13-EG-000190'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
