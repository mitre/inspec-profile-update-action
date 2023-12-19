control 'SV-237918' do
  title 'All IBM z/VM TCP/IP Ports must be restricted to ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'For each TCP/IP server defined examine the TCP/IP Configuration Port Statements.

Consult DISA Ports, Protocols, and Services Management (PPSM) Category Assurance Levels (CAL).

Verify that the ports and protocols being used are not prohibited and are necessary for the operation of the application server and the hosted applications.

If any of the ports or protocols is prohibited or not necessary for the application server operation, this is a finding.'
  desc 'fix', 'Configure the application server definition in TCP/IP configuration file to disable any ports or protocols that are prohibited by the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41128r649592_chk'
  tag severity: 'medium'
  tag gid: 'V-237918'
  tag rid: 'SV-237918r649594_rule'
  tag stig_id: 'IBMZ-VM-000630'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-41087r649593_fix'
  tag 'documentable'
  tag legacy: ['SV-93589', 'V-78883']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
