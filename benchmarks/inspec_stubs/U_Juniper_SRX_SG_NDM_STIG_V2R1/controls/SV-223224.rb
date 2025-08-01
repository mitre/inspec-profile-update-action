control 'SV-223224' do
  title 'For nonlocal maintenance sessions using SNMP, the Juniper SRX Services Gateway must use and securely configure SNMPv3 with SHA to protect the integrity of maintenance and diagnostic communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 
 
The Juniper SRX allows the use of SNMP to monitor or query the device in support of diagnostics information. SNMP cannot be used to make configuration changes; however, it is a valuable diagnostic tool. SNMP is disabled by default and must be enabled for use. SNMPv3 is the DoD-required version, but must be configured to be used securely.'
  desc 'check', 'Verify SNMP is configured for version 3.

[edit]
show snmp v3
 
If SNMPv3 is not configured for version 3 using SHA, this is a finding.'
  desc 'fix', 'Configure snmp to use version 3 with SHA authentication.

[edit]
set snmp v3 usm local-engine user <NAME> authentication-sha'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24897r513359_chk'
  tag severity: 'high'
  tag gid: 'V-223224'
  tag rid: 'SV-223224r513361_rule'
  tag stig_id: 'JUSX-DM-000146'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-24885r513360_fix'
  tag 'documentable'
  tag legacy: ['SV-80943', 'V-66453']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
