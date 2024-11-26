control 'SV-254203' do
  title 'Nutanix AOS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Confirm Nutanix AOS prohibits or restricts the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

$ sudo iptables -S

If IPv6 is in use:
$ sudo ip6tables -S

Review the site or program PPSM CAL; verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.'
  desc 'fix', 'Configure the system to restrict the use of functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments by running the following command:

$ sudo salt-call state.sls security/CVM/iptables/init'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57688r846695_chk'
  tag severity: 'medium'
  tag gid: 'V-254203'
  tag rid: 'SV-254203r846697_rule'
  tag stig_id: 'NUTX-OS-001160'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-57639r846696_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
