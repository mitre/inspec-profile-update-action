control 'SV-45786' do
  title 'The portmap or rpcbind service must not be installed unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'Check if the portmap and/or rpcbind packages are installed.
# rpm –q portmap rpcbind

If a package is found, this is a finding.'
  desc 'fix', 'Remove the portmap and/or rpcbind packages.
# rpm -e portmap rpcbind
# SuSEconfig'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22430'
  tag rid: 'SV-45786r1_rule'
  tag stig_id: 'GEN003815'
  tag gtitle: 'GEN003815'
  tag fix_id: 'F-39180r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
