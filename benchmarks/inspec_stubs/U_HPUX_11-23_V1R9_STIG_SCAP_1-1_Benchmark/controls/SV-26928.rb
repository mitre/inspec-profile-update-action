control 'SV-26928' do
  title 'The system must not have IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering.'
  desc 'fix', 'Edit the /etc/rc.config.d/netconf* files and remove the tunnel configurations.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22547'
  tag rid: 'SV-26928r1_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'GEN007820'
  tag fix_id: 'F-24172r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
