control 'SV-218510' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'Check the status of the portmap service.
# service portmap status
If the service is running, this is a finding.'
  desc 'fix', 'Shutdown and disable the portmap service.
# service portmap stop; chkconfig portmap off'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19985r555728_chk'
  tag severity: 'medium'
  tag gid: 'V-218510'
  tag rid: 'SV-218510r603259_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19983r555729_fix'
  tag 'documentable'
  tag legacy: ['V-22429', 'SV-63995']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
