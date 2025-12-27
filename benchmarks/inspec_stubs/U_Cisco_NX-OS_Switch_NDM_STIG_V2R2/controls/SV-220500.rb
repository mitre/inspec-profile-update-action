control 'SV-220500' do
  title 'The Cisco switch must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

snmp-server user NETOPS network-operator auth sha 0xb40efa3f311006de39b9d0725e663277d84ca332 localizedkey
snmp-server host 10.1.48.10 traps version 3 auth NETOPS

Authentication used by the SNMP users can be viewed via the show snmp user command as shown in the example below:

SW1# show snmp user
______________________________________________________________
 SNMP USERS 
______________________________________________________________

User Auth Priv(enforce) Groups acl_filter 
____ ____ ___________ ______ __________ 
NETOPS sha no network-operator 

If the Cisco switch is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to authenticate SNMP messages as shown in the example below:

SW1(config)# snmp-server user NETOPS auth sha xxxxxxxxxxxxxxxxx
SW1(config)# snmp-server host 10.1.48.10 traps version 3 auth NETOPS'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22215r539221_chk'
  tag severity: 'medium'
  tag gid: 'V-220500'
  tag rid: 'SV-220500r604141_rule'
  tag stig_id: 'CISC-ND-001130'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-22204r539222_fix'
  tag 'documentable'
  tag legacy: ['SV-110649', 'V-101545']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
