control 'SV-216538' do
  title 'The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

snmp-server host x.x.x.x traps version 3 auth V3USER
snmp-server user V3USER V3GROUP v3 auth sha 
snmp-server view V3READ iso included
snmp-server view V3WRITE iso included
snmp-server group V3GROUP v3 auth read V3READ write V3WRITE

If the Cisco router is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the Cisco router to authenticate SNMP messages as shown in the example below.

RP/0/0/CPU0:R3(config)#snmp-server group V3GROUP v3 auth read V3READ write V3WRITE
RP/0/0/CPU0:R3(config)#snmp-server user V3USER V3GROUP v3 auth sha xxxxxx 
RP/0/0/CPU0:R3(config)#snmp-server view V3READ iso included
RP/0/0/CPU0:R3(config)#snmp-server view V3WRITE iso included
RP/0/0/CPU0:R3(config)#snmp-server host x.x.x.x version 3 auth V3USER'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17773r288300_chk'
  tag severity: 'medium'
  tag gid: 'V-216538'
  tag rid: 'SV-216538r879768_rule'
  tag stig_id: 'CISC-ND-001130'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-17770r288301_fix'
  tag 'documentable'
  tag legacy: ['SV-105601', 'V-96463']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
