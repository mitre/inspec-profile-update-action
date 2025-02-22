control 'SV-26094' do
  title 'The portmap or rpcbind service must not be installed unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'If the system needs the portmap service to operate, this is not applicable.  Consult vendor documentation to determine the name and location of the portmap service.  Determine if the portmap service is installed.  If so, this is a finding.'
  desc 'fix', 'If the portmap or rpcbind service is part of a removable package, consult vendor documentation for the procedure to remove the package.  If the service cannot be removed, prevent service activation by removing all permissions from the executable.

Procedure:
# chmod 0000 <path to daemon>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29262r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22430'
  tag rid: 'SV-26094r1_rule'
  tag stig_id: 'GEN003815'
  tag gtitle: 'GEN003815'
  tag fix_id: 'F-27395r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
