control 'SV-246946' do
  title 'ONTAP must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Use "system services firewall policy show" to see all of the configured firewall policies defined in ONTAP.

Use "network interface show -fields firewall-policy" to see which network logical interfaces (LIFs) have which firewall policies configured.

Note: Because the cluster LIF is completely open with no configurable firewall policy, it must be on a private IP subnet on a secure isolated network.

If ONTAP cannot be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, this is a finding.'
  desc 'fix', 'Configure ONTAP new or modify ONTAP firewall policies with "system services firewall policy create or modify" to allow specific IP addresses to access specific network services or ports.

Configure logical interfaces to use firewall policies with "network interface modify -firewall-policy <firewall_policy_name> -lif <logical_interface_name>".'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50378r769168_chk'
  tag severity: 'high'
  tag gid: 'V-246946'
  tag rid: 'SV-246946r769170_rule'
  tag stig_id: 'NAOT-CM-000009'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-50332r769169_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
