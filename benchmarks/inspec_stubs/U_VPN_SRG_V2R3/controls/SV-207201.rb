control 'SV-207201' do
  title 'The VPN Gateway must protect log information from unauthorized read access if all or some of this data is stored locally.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured VPN gateway. Thus, it is imperative that the collected log data from the various VPN gateways, as well as the auditing tools, be secured and can only be accessed by authorized personnel.

This requirement pertains to securing the VPN log as it is stored locally, on the box temporarily, or while being encapsulated.'
  desc 'check', 'Verify the VPN Gateway protects log information from unauthorized read access if all or some of this data is stored locally.

If the VPN Gateway does not protect log information from unauthorized read access if all or some of this data is stored locally, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to protect log information from unauthorized read access if all or some of this data is stored locally.'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7461r378224_chk'
  tag severity: 'low'
  tag gid: 'V-207201'
  tag rid: 'SV-207201r608988_rule'
  tag stig_id: 'SRG-NET-000098-VPN-000370'
  tag gtitle: 'SRG-NET-000098'
  tag fix_id: 'F-7461r378225_fix'
  tag 'documentable'
  tag legacy: ['SV-106211', 'V-97073']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
