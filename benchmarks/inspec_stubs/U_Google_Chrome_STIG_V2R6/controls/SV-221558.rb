control 'SV-221558' do
  title 'Firewall traversal from remote host must be disabled.'
  desc 'Remote connections should never be allowed that bypass the firewall, as there is no way to verify if they can be trusted. Enables usage of STUN and relay servers when remote clients are trying to establish a connection to this machine. If this setting is enabled, then remote clients can discover and connect to this machine even if they are separated by a firewall. If this setting is disabled and outgoing UDP connections are filtered by the firewall, then this machine will only allow connections from client machines within the local network. If this policy is left not set the setting will be enabled.'
  desc 'check', 'Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If RemoteAccessHostFirewallTraversal is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a finding.

Windows registry:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the RemoteAccessHostFirewallTraversal value name does not exist or its value data is not set to 0, then this is a finding.'
  desc 'fix', 'Windows group policy:
 1. Open the group policy editor tool with gpedit.msc 
 2. Navigate to Policy Path: Computer Configuration\\Administrative\\Templates\\Google\\Google Chrome\\Remote Access
 Policy Name: Enable firewall traversal from remote access host
 Policy State: Disabled
 Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23273r415801_chk'
  tag severity: 'medium'
  tag gid: 'V-221558'
  tag rid: 'SV-221558r769351_rule'
  tag stig_id: 'DTBC-0001'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-23262r769350_fix'
  tag 'documentable'
  tag legacy: ['SV-57545', 'V-44711']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
