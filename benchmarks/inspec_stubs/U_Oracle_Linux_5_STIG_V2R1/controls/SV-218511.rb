control 'SV-218511' do
  title 'The portmap or rpcbind service must not be installed unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'Check if the portmap package is installed.
# rpm -qa | grep portmap
If a package is found, this is a finding.'
  desc 'fix', 'Remove the portmap package.
# rpm -e portmap
or 
# yum remove portmap'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19986r562663_chk'
  tag severity: 'medium'
  tag gid: 'V-218511'
  tag rid: 'SV-218511r603259_rule'
  tag stig_id: 'GEN003815'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19984r562664_fix'
  tag 'documentable'
  tag legacy: ['V-22430', 'SV-63997']
  tag cci: ['CCI-000305', 'CCI-000381']
  tag nist: ['CM-7 (2)', 'CM-7 a']
end
