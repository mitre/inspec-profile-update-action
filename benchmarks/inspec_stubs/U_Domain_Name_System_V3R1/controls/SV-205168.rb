control 'SV-205168' do
  title 'The DNS server implementation must be configured to prohibit or restrict unapproved ports and protocols.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements by providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', "Review the DNS system configuration to ensure the system is configured for incoming traffic only on UDP/53 and TCP/53 and outgoing DNS traffic sent from a random port rather than the DNS software's default port.

If the DNS implementation is not configured for incoming traffic on UDP/53 and TCP/53 and outgoing traffic sent from a random port rather than the DNS software's default port, this is a finding."
  desc 'fix', "Configure the DNS implementation for incoming traffic on UDP/53 and TCP/53 and outgoing traffic sent from a random port rather than the DNS software's default port."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5435r392420_chk'
  tag severity: 'medium'
  tag gid: 'V-205168'
  tag rid: 'SV-205168r879588_rule'
  tag stig_id: 'SRG-APP-000142-DNS-000014'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-5435r392421_fix'
  tag 'documentable'
  tag legacy: ['SV-69043', 'V-54797']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
