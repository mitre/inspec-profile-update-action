control 'SV-253900' do
  title 'The Juniper EX switch must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Determine if the network device prohibits the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.

Verify unnecessary or nonsecure functions are not configured or are explicitly disabled. For example, FTP and Telnet are nonsecure. Verify these services are not enabled as in the example below:
[edit system services]
ftp;
telnet;

If any unnecessary or nonsecure functions are permitted, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.

delete system services ftp
delete system services telnet
delete system services web-management

Note: Delete other configured but unnecessary system services.'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57352r843731_chk'
  tag severity: 'high'
  tag gid: 'V-253900'
  tag rid: 'SV-253900r843733_rule'
  tag stig_id: 'JUEX-NM-000230'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-57303r843732_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
