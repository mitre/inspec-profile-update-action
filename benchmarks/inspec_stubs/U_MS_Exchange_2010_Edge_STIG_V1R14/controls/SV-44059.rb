control 'SV-44059' do
  title 'Sender reputation filter must be enabled.'
  desc 'By performing filtering at the perimeter, up to 90% of SPAM, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the Mail server environment.  Sender reputation is anti-SPAM functionality that blocks messages according to many characteristics of the sender. Sender reputation relies on persisted data about the sender to determine what action, if any, to take on an inbound message. This setting enables the sender reputation function.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:
 
Get-SenderReputationConfig | Select Enabled

If the value of 'Enabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:
 
Set-SenderReputationConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33639'
  tag rid: 'SV-44059r1_rule'
  tag stig_id: 'Exch-2-321'
  tag gtitle: 'Exch-2-321'
  tag fix_id: 'F-37532r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
