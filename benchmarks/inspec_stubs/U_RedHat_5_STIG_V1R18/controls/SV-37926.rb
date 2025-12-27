control 'SV-37926' do
  title 'The system must not be running any routing protocol daemons, unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers.  If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', "Check for any running routing protocol daemons. If the system is a VM host and acts as a router solely for the benefits of its client systems, then this rule is not applicable.

# chkconfig --list |grep :on|egrep '(ospf|route|bgp|zebra|quagga)'
If any routing protocol daemons are listed, this is a finding."
  desc 'fix', 'Disable any routing protocol daemons.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37168r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22665'
  tag rid: 'SV-37926r1_rule'
  tag stig_id: 'GEN005590'
  tag gtitle: 'GEN005590'
  tag fix_id: 'F-32420r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
