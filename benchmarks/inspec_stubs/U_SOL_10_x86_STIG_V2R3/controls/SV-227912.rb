control 'SV-227912' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30074r490141_chk'
  tag severity: 'medium'
  tag gid: 'V-227912'
  tag rid: 'SV-227912r603266_rule'
  tag stig_id: 'GEN005590'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30062r490142_fix'
  tag 'documentable'
  tag legacy: ['V-22665', 'SV-39878']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
