control 'SV-80689' do
  title 'The HP FlexFabric Switch must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the HP FlexFabric Switch must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Check if unsecured protocols and services are disabled on the HP FlexFabric Switch:

[HP] display ftp-server

FTP is not configured.

[HP] display current-configuration | include telnet

Note: When Telnet server is enabled, the output for this command is telnet server enable.

If all unnecessary and non-secure functions, ports, protocols, and services are not disabled, this is a finding.'
  desc 'fix', 'Disable unsecure protocols and services on the HP FlexFabric Switch:

[HP] undo ftp server enable
[HP] undo telnet server enable

Note: By default, both FTP and Telnet services are disabled.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66199'
  tag rid: 'SV-80689r1_rule'
  tag stig_id: 'HFFS-ND-000046'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-72275r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
