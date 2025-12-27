control 'SV-227005' do
  title 'The system must not be running any routing protocol daemons, unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers.  If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', "Check for any running routing protocol daemons.
# svcs -a | grep online | egrep '(ospf|route|bgp|zebra|quagga)'
OR
# ps -ef | egrep '(ospf|route|bgp|zebra|quagga)'
If any routing protocol daemons are listed, this is a finding."
  desc 'fix', 'Disable any routing protocol daemons.

# svcadm disable <routing protocol daemon>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29167r485354_chk'
  tag severity: 'medium'
  tag gid: 'V-227005'
  tag rid: 'SV-227005r603265_rule'
  tag stig_id: 'GEN005590'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29155r485355_fix'
  tag 'documentable'
  tag legacy: ['V-22665', 'SV-39878']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
