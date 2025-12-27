control 'SV-206646' do
  title 'The layer 2 switch must be configured to disable non-essential capabilities.'
  desc 'A compromised switch introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each switch is to enable only the capabilities required for operation.'
  desc 'check', 'Review the switch configuration to determine if services or functions not required for operation, or not related to switch functionality, are enabled.

If unnecessary services and functions are enabled on the switch, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the switch. Removal is recommended since the service or function may be inadvertently enabled otherwise. However, if removal is not possible, disable the service or function.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6904r298368_chk'
  tag severity: 'medium'
  tag gid: 'V-206646'
  tag rid: 'SV-206646r382903_rule'
  tag stig_id: 'SRG-NET-000131-L2S-000014'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-6904r298369_fix'
  tag 'documentable'
  tag legacy: ['SV-76555', 'V-62065']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
