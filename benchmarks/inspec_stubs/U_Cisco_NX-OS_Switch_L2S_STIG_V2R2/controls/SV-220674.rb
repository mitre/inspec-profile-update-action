control 'SV-220674' do
  title 'The Cisco switch must be configured to disable non-essential capabilities.'
  desc 'A compromised switch introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each switch is to enable only the capabilities required for operation.'
  desc 'check', 'Verify that the switch does not have any unnecessary or non-secure ports, protocols, and services enabled. For example, the following features such as telnet should never be enabled, while other features should only be enabled if required for operations.

feature telnet
feature wccp
feature nxapi
feature imp

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.'
  desc 'fix', 'Disable features that should not be enabled unless required for operations.

SW2(config)# no feature telnet
SW2(config)# no feature wccp
SW2(config)# no feature nxapi
SW2(config)# no feature imp

Note: Telnet must always be disabled.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22389r539073_chk'
  tag severity: 'medium'
  tag gid: 'V-220674'
  tag rid: 'SV-220674r539671_rule'
  tag stig_id: 'CISC-L2-000010'
  tag gtitle: 'SRG-NET-000131-L2S-000014'
  tag fix_id: 'F-22378r539074_fix'
  tag 'documentable'
  tag legacy: ['SV-110323', 'V-101219']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
