control 'SV-45728' do
  title 'The system must log martian packets.'
  desc 'Martian packets are packets containing addresses known by the system to be invalid.  Logging these messages allows the SA to identify misconfigurations or attacks in progress.'
  desc 'check', 'Verify the system logs martian packets.

# grep [01] /proc/sys/net/ipv4/conf/*/log_martians|egrep "default|all"

If all of the resulting lines do not end with "1", this is a finding.'
  desc 'fix', 'Configure the system to log martian packets.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.log_martians=1" and "net.ipv4.conf.default.log_martians=1". 

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43095r1_chk'
  tag severity: 'low'
  tag gid: 'V-22418'
  tag rid: 'SV-45728r1_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'GEN003611'
  tag fix_id: 'F-39126r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
