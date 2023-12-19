control 'SV-208942' do
  title 'The rdisc service must not be running.'
  desc 'General-purpose systems typically have their network and routing information configured statically by a system administrator. Workstations or some special-purpose systems often use DHCP (instead of IRDP) to retrieve dynamic network configuration information.'
  desc 'check', 'To check that the "rdisc" service is disabled in system boot configuration, run the following command: 

# chkconfig "rdisc" --list

Output should indicate the "rdisc" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "rdisc" --list
"rdisc" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "rdisc" is disabled through current runtime configuration: 

# service rdisc status

If the service is disabled the command will return the following output: 

rdisc is stopped

If the service is running, this is a finding.'
  desc 'fix', 'The "rdisc" service implements the client side of the ICMP Internet Router Discovery Protocol (IRDP), which allows discovery of routers on the local subnet. If a router is discovered then the local routing table is updated with a corresponding default route. By default this daemon is disabled. The "rdisc" service can be disabled with the following commands: 

# chkconfig rdisc off
# service rdisc stop'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9195r357806_chk'
  tag severity: 'low'
  tag gid: 'V-208942'
  tag rid: 'SV-208942r603263_rule'
  tag stig_id: 'OL6-00-000268'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9195r357807_fix'
  tag 'documentable'
  tag legacy: ['SV-65049', 'V-50843']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
