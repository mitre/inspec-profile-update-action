control 'SV-221238' do
  title 'The Exchange Sender Reputation filter must identify the spam block level.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. Sender Reputation is antispam functionality that blocks messages according to many characteristics of the sender. Sender Reputation relies on persisted data about the sender to determine what action, if any, to take on an inbound message. This setting enables the threshold at which an email will be considered spam.'
  desc 'check', 'Note: If third-party anti-spam product is being used, the anti-spam product must be configured to meet the requirement.

Review the Email Domain Security Plan (EDSP).

Determine the SrlBlockThreshold value. 

Open the Exchange Management Shell and enter the following command:
 
Get-SenderReputationConfig | Select Name, SrlBlockThreshold

If the value of SrlBlockThreshold is not set to "6", this is a finding.

or

If the value of "SrlBlockThreshold" is set to a value other than "6" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP to reflect the SrlBlockThreshold size. 

Open the Exchange Management Shell and enter the following command:

Set-SenderReputationConfig -SrlBlockThreshold 6

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22953r411840_chk'
  tag severity: 'medium'
  tag gid: 'V-221238'
  tag rid: 'SV-221238r612603_rule'
  tag stig_id: 'EX16-ED-000390'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22942r411841_fix'
  tag 'documentable'
  tag legacy: ['SV-95267', 'V-80557']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
