control 'SV-218487' do
  title 'The system must not send IPv4 Internet Control Message Protocol (ICMP) redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination.  These messages contain information from the system's route table possibly revealing portions of the network topology."
  desc 'check', 'Verify the system does not send IPv4 ICMP redirect messages.

# grep [01] /proc/sys/net/ipv4/conf/*/send_redirects|egrep "default|all"

If all of the resulting lines do not end with "0", this is a finding.'
  desc 'fix', 'Configure the system to not send IPv4 ICMP redirect messages.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.send_redirects=0" and "net.ipv4.conf.default.send_redirects=0". 
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19962r555659_chk'
  tag severity: 'medium'
  tag gid: 'V-218487'
  tag rid: 'SV-218487r603259_rule'
  tag stig_id: 'GEN003610'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-19960r555660_fix'
  tag 'documentable'
  tag legacy: ['V-22417', 'SV-64205']
  tag cci: ['CCI-000382', 'CCI-001551', 'CCI-001503']
  tag nist: ['CM-7 b', 'AC-4', 'CM-6 d']
end
