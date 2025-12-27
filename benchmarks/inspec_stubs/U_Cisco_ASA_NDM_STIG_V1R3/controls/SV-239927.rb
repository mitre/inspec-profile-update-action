control 'SV-239927' do
  title 'The Cisco ASA must be configured to authenticate Simple Network Management Protocol (SNMP) messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement as shown in the example below.

snmp-server group NETOPS v3 priv 
snmp-server user FWADMIN NETOPS v3 engineID xxxxxxxxxxxx encrypted auth sha xxxxxxxxxxxxxxxx 
snmp-server host NDM_INTERFACE 10.1.48.10  version 3 FWADMIN

If the Cisco ASA is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to authenticate SNMP messages as shown in the example below.

ASA(config)# snmp-server group NETOPS v3 priv
ASA(config)# snmp-server user FWADMIN NETOPS v3 auth sha xxxxxxxxxxxxxxx
ASA(config)# snmp-server host NDM_INTERFACE 10.1.48.10  version 3 FWADMIN 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43160r666142_chk'
  tag severity: 'medium'
  tag gid: 'V-239927'
  tag rid: 'SV-239927r851032_rule'
  tag stig_id: 'CASA-ND-001050'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-43119r666143_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
