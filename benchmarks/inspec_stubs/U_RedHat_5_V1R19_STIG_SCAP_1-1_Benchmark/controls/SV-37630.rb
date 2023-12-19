control 'SV-37630' do
  title 'The system must log martian packets.'
  desc 'Martian packets are packets containing addresses known by the system to be invalid.  Logging these messages allows the SA to identify misconfigurations or attacks in progress.'
  desc 'fix', 'Configure the system to log martian packets.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.log_martians=1" and "net.ipv4.conf.default.log_martians=1". 

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22418'
  tag rid: 'SV-37630r1_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'GEN003611'
  tag fix_id: 'F-31667r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
