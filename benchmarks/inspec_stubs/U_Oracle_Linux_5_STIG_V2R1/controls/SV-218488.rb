control 'SV-218488' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19963r555662_chk'
  tag severity: 'low'
  tag gid: 'V-218488'
  tag rid: 'SV-218488r603259_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19961r555663_fix'
  tag 'documentable'
  tag legacy: ['V-22418', 'SV-64207']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
