control 'SV-37629' do
  title 'The system must not send IPv4 Internet Control Message Protocol (ICMP) redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination.  These messages contain information from the system's route table possibly revealing portions of the network topology."
  desc 'fix', 'Configure the system to not send IPv4 ICMP redirect messages.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.send_redirects=0" and "net.ipv4.conf.default.send_redirects=0". 
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22417'
  tag rid: 'SV-37629r1_rule'
  tag stig_id: 'GEN003610'
  tag gtitle: 'GEN003610'
  tag fix_id: 'F-31666r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
