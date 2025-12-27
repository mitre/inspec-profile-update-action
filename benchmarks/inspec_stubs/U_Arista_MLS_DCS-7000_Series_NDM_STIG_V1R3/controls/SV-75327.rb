control 'SV-75327' do
  title 'Arista Multilayer Switches used for nonlocal maintenance sessions must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP.'
  desc 'check', 'Determine if the network device uses secure protocols instead of their unsecured counterparts. 

If any unsecured maintenance protocols are in use (e.g., telnet, FTP, HTTP) and these protocols are not wrapped in a secure tunnel, this is a finding.

Validate by checking that unsecure protocols are either disabled or wrapped in SSH tunnels.

Executing a "show run" command will provide a means to validate this config. From the output of this command, verify that there is no statement enabling telnet, there is no statement enabling FTP, and there is no statement enabling the API, or the API is configured to use only HTTPS.'
  desc 'fix', 'Configure the network device to use secure protocols instead of their unsecured counterparts.

Configuration Example: 

Disable unsecure protocols.
configure
management telnet
shutdown
exit
management api http-commands
no protocol http
protocol https
exit 

Other protocols (FTP) can be denied using AAA and RBAC. For connections that require use of these maintenance protocols, creation of SSH tunnels can fulfill this security requirement. This is summarized here and available at length in the Common Criteria guidance document.

Configuration Example: 

management ssh
tunnel NEW
local port 514
ssh-server syslogServer user authuser port 22
remote host localhost port 514
no shutdown'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60869'
  tag rid: 'SV-75327r1_rule'
  tag stig_id: 'AMLS-NM-000340'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-66581r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
