control 'SV-255952' do
  title 'The Arista network device must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify the Arista network device has telnet and https disabled.

Step 1: Determine if telnet is disabled with the following command:

switch#show management telnet

Telnet status for Default VRF is disabled 
Telnet session limit is 20
Telnet session limit per host is 20

If telnet is enabled, this is a finding.

Step 2: Determine if https is disabled with the following command:

switch#show management http-server

SSL Profile:        none
FIPS Mode:          No
QoS DSCP:           0
LogLevel:           none
CSP Frame Ancestor: None
TLS Protocols:      1.0 1.1 1.2
   VRF           Server Status         Enabled Services
-------------------------------------------------------
   default       HTTPS: port 443       http-commands

If Enabled Services in the output shows http-commands, this is a finding.'
  desc 'fix', 'Configure the Arista network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.

Step 1: Disable telnet with the following command:

switch#config
switch(config)#management telnet
switch(config-mgmt-telnet)#shutdown
switch(config-mgmt-telnet)#exit
switch(config)#exit

Step 2: Disable https with the following command:

switch#config
switch(config)#management api http-commands
switch(config-mgmt-api-http-commands)#shutdown
switch(config-mgmt-api-http-commands)#exit
switch(config)#exit'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59628r882196_chk'
  tag severity: 'high'
  tag gid: 'V-255952'
  tag rid: 'SV-255952r882198_rule'
  tag stig_id: 'ARST-ND-000340'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-59571r882197_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
