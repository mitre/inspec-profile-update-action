control 'SV-218622' do
  title 'The system must not be running any routing protocol daemons, unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers.  If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', "Check for any running routing protocol daemons. If the system is a VM host and acts as a router solely for the benefits of its client systems, then this rule is not applicable.

# chkconfig --list |grep :on|egrep '(ospf|route|bgp|zebra|quagga)'

If any routing protocol daemons are listed, this is a finding."
  desc 'fix', 'Disable any routing protocol daemons.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20097r556064_chk'
  tag severity: 'medium'
  tag gid: 'V-218622'
  tag rid: 'SV-218622r603259_rule'
  tag stig_id: 'GEN005590'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20095r556065_fix'
  tag 'documentable'
  tag legacy: ['V-22665', 'SV-64111']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
