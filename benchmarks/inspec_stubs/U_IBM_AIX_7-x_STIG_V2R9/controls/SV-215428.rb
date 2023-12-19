control 'SV-215428' do
  title 'AIX must not run any routing protocol daemons unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', "Check for any running routing protocol daemons by running:
# ps -ef | egrep '(ospf|route|bgp|zebra|quagga|gate)' 

If any routing protocol daemons are listed, this is a finding."
  desc 'fix', %q(Kill any routing protocol daemons by running the following command:
# ps -ef |egrep '(ospf|route|bgp|zebra|quagga|gate)' | grep -v egrep | awk -F " " '{print $2}' | while read pid;do kill $pid;done)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16626r294735_chk'
  tag severity: 'medium'
  tag gid: 'V-215428'
  tag rid: 'SV-215428r508663_rule'
  tag stig_id: 'AIX7-00-003133'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16624r294736_fix'
  tag 'documentable'
  tag legacy: ['V-91717', 'SV-101815']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
