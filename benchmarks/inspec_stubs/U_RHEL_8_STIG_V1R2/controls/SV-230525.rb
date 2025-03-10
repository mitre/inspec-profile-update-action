control 'SV-230525' do
  title 'A firewall must be able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of RHEL 8 to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exists to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

Since version 0.6.0, "firewalld" has incorporated "nftables" as its backend support. Utilizing the limit statement in "nftables" can help to mitigate DoS attacks.'
  desc 'check', 'Verify "nftables" is configured to allow rate limits on any connection to the system with the following commands:

Check that the "nftables.service" is active and running:

$ sudo systemctl status nftables.service

nftables.service - Netfilter Tables
Loaded: loaded (/usr/lib/systemd/system/nftables.service; enabled; vendor preset: disabled)
Active: active (running)

Verify "firewalld" has "nftables" set as the default backend:

$ sudo grep -i firewallbackend /etc/firewalld/firewalld.conf

# FirewallBackend
FirewallBackend=nftables

If the "nftables" is not active, running and set as the "firewallbackend" default, this is a finding.'
  desc 'fix', 'Install "nftables" packages onto the host with the following commands:

$ sudo yum install nftables.x86_64     1:0.9.0-14.el8

Configure the "nftables" service to automatically start after reboot with the following command:

$ sudo systemctl enable nftables.service

Configure "nftables" to be the default "firewallbackend" for "firewalld" by adding or editing the following line in "etc/firewalld/firewalld.conf":

FirewallBackend=nftables

Establish rate-limiting rules based on organization-defined types of DoS attacks on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33194r568321_chk'
  tag severity: 'medium'
  tag gid: 'V-230525'
  tag rid: 'SV-230525r627750_rule'
  tag stig_id: 'RHEL-08-040150'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-33169r568322_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
