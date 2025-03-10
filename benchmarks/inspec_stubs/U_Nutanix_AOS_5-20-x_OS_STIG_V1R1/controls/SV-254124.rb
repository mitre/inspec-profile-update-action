control 'SV-254124' do
  title 'Nutanix AOS must control remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
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
  tag check_id: 'C-57609r846458_chk'
  tag severity: 'medium'
  tag gid: 'V-254124'
  tag rid: 'SV-254124r846460_rule'
  tag stig_id: 'NUTX-OS-000070'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-57560r846459_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
