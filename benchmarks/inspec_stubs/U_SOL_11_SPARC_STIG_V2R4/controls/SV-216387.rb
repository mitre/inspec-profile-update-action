control 'SV-216387' do
  title 'The boundary protection system (firewall) must be configured to deny network traffic by default and must allow network traffic by exception (i.e., deny all, permit by exception).'
  desc 'A firewall that relies on a deny all, permit by exception strategy requires all traffic to have explicit permission before traversing an interface on the host. The firewall must incorporate stateful packet filtering and logging.
Non-local maintenance and diagnostic communications often contain sensitive information and must be protected. The security of these remote accesses can be ensured by sending non-local maintenance and diagnostic communications through encrypted channels enforced via firewall configurations.
'
  desc 'check', 'Ensure that either the IP Filter or Packet Filter Firewall is installed correctly.

Determine the OS version you are currently securing.
# uname -v

For Solaris 11, 11.1, 11.2, and 11.3, that use IP Filter, the IP Filter Management profile is required.

Check that the IP Filter firewall is enabled and configured so that only authorized sessions are allowed.

# svcs ipfilter

If ipfilter is not listed with a state of online, this is a finding.

The IP Filter Management profile is required.

Check that the filters are configured properly.

# ipfstat -io

If the output of this command does not include these lines:

block out log all keep state keep frags
block in log all
block in log from any to 255.255.255.255/32
block in log from any to 127.0.0.1/32

This is a finding.

Even if the lines above are included in the output, it is possible that other lines can contradict the firewall settings. Review the firewall rules and ensure that they conform to organizational and mission requirements. If the firewall rules are not configured to organizational standards, this is a finding.

For Solaris 11.3 or newer, that use Packet Filter, the Network Firewall Management rights profile is required.

Check that the Packet Filter firewall is enabled and configured so that only authorized sessions are allowed.
# svcs firewall:default

If firewall is not listed with a state of "online", this is a finding.

The Network Firewall Management rights profile is required.
Check that the filters are configured properly.
# pfctl -s rules

If the output of this command does not include this line:

block drop log (to pflog0) all

This is a finding.
Check that the Packet Filter firewall logging daemon is enabled.
svcs firewall/pflog:default
If pflog is not listed with a state of "online", this is a finding.'
  desc 'fix', 'The root role is required.

For Solaris 11, 11.1, 11.2, and 11.3, that use IP Filter, configure and enable the IP Filters policy.

# pfedit /etc/ipf/ipf.conf. 

Add these lines to the file:

# Do not allow all outbound traffic, keep state, and log
block out log all keep state keep frags
# Block and log everything else that comes in
block in log all
block in log from any to 255.255.255.255
block in log from any to 127.0.0.1/32

Enable ipfilter.

# svcadm enable ipfilter

Notify ipfilter to use the new configuration file.

# ipf -Fa -f /etc/ipf/ipf.conf

For Solaris 11.3 or newer, that use Packet Filter, configure and enable the Packet Filter’s policy.
# pfedit /etc/firewall/pf.conf.

Add these lines to the file:

# Block and log all traffic on all interfaces in either direction from
# anywhere to anywhere
block log all

Enable Packet Filter.
# svcadm enable firewall:default
Enable Packet Filter logging daemon.
# svcadm enable firewall/pflog:default

Note: Because the default firewall rules block all network access to the system, ensure that there is still a method to access the system such as SSH or console access prior to activating the firewall rules. Operational requirements may dictate the addition of protocols such as SSH, DNS, NTP, HTTP, and HTTPS to be allowed.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17623r744129_chk'
  tag severity: 'medium'
  tag gid: 'V-216387'
  tag rid: 'SV-216387r744131_rule'
  tag stig_id: 'SOL-11.1-050240'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17621r744130_fix'
  tag satisfies: ['SRG-OS-000074', 'SRG-OS-000096', 'SRG-OS-000112', 'SRG-OS-000113', 'SRG-OS-000125', 'SRG-OS-000250', 'SRG-OS-000393']
  tag 'documentable'
  tag legacy: ['SV-61107', 'V-48235']
  tag cci: ['CCI-000197', 'CCI-000366', 'CCI-000382', 'CCI-000877', 'CCI-001453', 'CCI-001941', 'CCI-001942', 'CCI-002890']
  tag nist: ['IA-5 (1) (c)', 'CM-6 b', 'CM-7 b', 'MA-4 c', 'AC-17 (2)', 'IA-2 (8)', 'IA-2 (9)', 'MA-4 (6)']
end
