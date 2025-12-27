control 'SV-255959' do
  title 'The Arista network device must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the network device configuration to verify SNMP messages are authenticated using a FIPS-validated HMAC.

Verify the Arista network device is configured for the following SNMP example parameters:

switch(config)#show run | section snmp
snmp-server engineID local f5717f444ca880dbb200
snmp-server chassis-id ID CC-7050X3
snmp-server contact FedSE
snmp-server location JITC
snmp-server view snmpview system included
snmp-server group testers v3 priv read snmpview
snmp-server user jitc-sw testers v3 localized f8527f444ca990dcc200 auth sha 7b65225a6abf5111cd951e6cb7e105aef5bcd734 priv aes a1aedb1986642e766d4c8032d58e73b72bc3528b
snmp-server host 192.168.10.31 version 3 priv jitc-sw
snmp-server enable traps snmp authentication
snmp-server enable traps snmp link-down
snmp-server enable traps snmp link-up
!

If the Arista network device is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate SNMP messages using a FIPS-validated HMAC.

Configure the Arista network device following the example SNMP parameters to ensure messages are authenticated using FIPS-validated HMAC:

switch(config)#snmp-server engineID local f5717f444ca880dbb200
switch(config)#snmp-server chassis-id ID CC-7050X3
switch(config)#snmp-server contact FedSE
switch(config)#snmp-server location JITC
switch(config)#snmp-server view snmpview system included
switch(config)#snmp-server group testers v3 priv read snmpview
switch(config)#snmp-server user jitc-sw testers v3 localized f8527f444ca990dcc200 auth sha 7b65225a6abf5111cd951e6cb7e105aef5bcd734 priv aes a1aedb1986642e766d4c8032d58e73b72bc3528b
switch(config)#snmp-server host 192.168.10.31 version 3 priv jitc-sw
switch(config)#snmp-server enable traps snmp authentication
switch(config)#snmp-server enable traps snmp link-down
switch(config)#snmp-server enable traps snmp link-up'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59635r882217_chk'
  tag severity: 'medium'
  tag gid: 'V-255959'
  tag rid: 'SV-255959r882219_rule'
  tag stig_id: 'ARST-ND-000660'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-59578r882218_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
