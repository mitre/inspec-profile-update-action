control 'SV-26093' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'If the portmap service is required for system operations, this is not a finding.  Determine if the portmap service is running.  If so, this is a finding.'
  desc 'fix', 'Disable the portmap service.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22429'
  tag rid: 'SV-26093r1_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'GEN003810'
  tag fix_id: 'F-26280r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
