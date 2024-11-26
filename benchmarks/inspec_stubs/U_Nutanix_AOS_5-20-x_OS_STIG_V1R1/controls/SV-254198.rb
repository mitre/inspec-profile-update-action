control 'SV-254198' do
  title 'Nutanix AOS must enable an application firewall, if available.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Confirm Nutanix AOS prohibits or restricts the use of remote access methods, using the iptables firewall service.

$ sudo service iptables status
iptables.service - IPv4 firewall with iptables
   Loaded: loaded (/usr/lib/systemd/system/iptables.service; enabled; vendor preset: disabled)
   Active: active (exited) since Mon 2021-08-02 15:02:12 CDT; 2 weeks 6 days ago
 Main PID: 1250 (code=exited, status=0/SUCCESS)
   CGroup: /system.slice/iptables.service

If IPv6 is in use:
$ sudo service ip6tables status
ip6tables.service - IPv6 firewall with ip6tables
   Loaded: loaded (/usr/lib/systemd/system/ip6tables.service; enabled; vendor preset: disabled)
   Active: active (exited) since Mon 2021-08-02 15:02:12 CDT; 2 weeks 6 days ago
 Main PID: 1313 (code=exited, status=0/SUCCESS)
   CGroup: /system.slice/ip6tables.service

If no iptables services are "Loaded" and "Active", this is a finding.'
  desc 'fix', 'Configure the system to restrict the use of remote access methods by running the following command.

$ sudo salt-call state.sls security/CVM/iptables/init'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57683r846680_chk'
  tag severity: 'medium'
  tag gid: 'V-254198'
  tag rid: 'SV-254198r846682_rule'
  tag stig_id: 'NUTX-OS-001110'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-57634r846681_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
