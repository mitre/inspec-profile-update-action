control 'SV-79579' do
  title 'The DataPower Gateway must have SSH and web management bound to the management interface and Telnet disabled.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems. Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

This requirement applies to applications, services, protocols, and ports used for network device management. NTP, SSH, HTTPS and SNMP are associated with device management, but, when used to manage the device, must be restricted to the management network.'
  desc 'check', 'Logon to the Default Domain.

Navigate to Network >> Management>> Web Management Service. If the Administrative State is not enabled, this is a finding.

Navigate to Network >> Management>> SSH Service. If the Administrative State is not enabled, this is a finding.

Navigate to Network >> Management>> Telnet Service. If the Administrative State is enabled, this is a finding.'
  desc 'fix', 'Log on to the Default Domain.

Navigate to Network >> Management>> Web Management Service. Set the Administrative State to enabled.

Navigate to Network >> Management>> SSH Service. Set the Administrative State to enabled.

In the Local IP Address field, enter the local IP address of the device monitors for incoming SSH requests.

Click "Apply" to save the changes to the running configuration.

Click "Save Config" to save the changes to the startup configuration.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65715r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65089'
  tag rid: 'SV-79579r1_rule'
  tag stig_id: 'WSDP-NM-000046'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-71029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
