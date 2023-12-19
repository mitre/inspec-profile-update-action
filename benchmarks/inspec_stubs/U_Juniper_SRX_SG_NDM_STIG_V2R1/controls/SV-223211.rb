control 'SV-223211' do
  title 'If SNMP is enabled, the Juniper SRX Services Gateway must use and securely configure SNMPv3.'
  desc "To prevent non-secure protocol communications with the organization's local SNMPv3 services, the SNMP client on the Juniper SRX must be configured for proper identification and strong cryptographically-based protocol for authentication.

SNMPv3 defines a user-based security model (USM), and a view-based access control model (VACM). SNMPv3 USM provides data integrity, data origin authentication, message replay protection, and protection against disclosure of the message payload. SNMPv3 VACM provides access control to determine whether a specific type of access (read or write) to the management information is allowed.

The Junos operating system allows the use of SNMPv3 to monitor or query the device for management purposes. Junos does not allow SNMPv3, of any type, to be used to make configuration changes to the device. SNMPv3 is disabled by default and must be enabled for use. SNMPv3 is the DoD-preferred method for monitoring the device securely. If SNMPv3 is not being used, it must be disabled. The following commands will configure SNMPv3. The Junos operating system allows the use of FIPS approved protocols for both authentication (SHA1) and for privacy (AES128). These protocols should be used to ensure secure management connections."
  desc 'check', 'Verify SNMPv3 is enabled and configured.

[edit]
show snmp

If an SNMP stanza does not exist, this is not a finding.

If SNMPv3 is not configured to meet DoD requirements, this is a finding.

If versions earlier than SNMPv3 are enabled, this is a finding.'
  desc 'fix', 'Enable and configure SNMPv3 and configure a trap and community string.

[edit]
set snmp location <LOCATION-NAME>
set snmp v3 usm local-engine user <USER-NAME> privacy-AES128
set snmp v3 vacm security-to-group security-model usm security-name <SECURITY-NAME> group <GROUP-NAME>
set snmp v3 vacm access group <GROUP-NAME> default-context-prefix security-model usm
security-level privacy read-view all
set snmp v3 vacm access group <GROUP-NAME> default-context-prefix security-model usm
security-level privacy notify-view all
set snmp v3 target-address <target-address-name> tag-list <SNMP-trap-receiver>
set snmp v3 target-address <TARGER-ADDRESS-NAME> target-parameters <PARMS-NAME>
set snmp v3 target-parameters <PARMS-NAME> parameters message-processing-model v3
set snmp v3 target-parameters <PARMS-NAME> parameters security-model usm
set snmp v3 target-parameters <PARMS-NAME> parameters security-level privacy
set snmp v3 target-parameters <PARMS-NAME> parameters security-name <SECURITY-NAME>
set snmp v3 target-parameters <PARMS-NAME> notify-filter device-traps
set snmp v3 notify <SNMP-TRAPS> type trap
set snmp v3 notify <SNMP-TRAPS> tag <SNMP-TRAP-RECEIVER>
set snmp v3 notify-filter device-traps oid jnxChassisTraps include
set snmp v3 notify-filter device-traps oid jnxChassisOKTraps include
set snmp v3 notify-filter device-traps oid system include
set snmp v3 notify-filter device-traps oid .1 include
set snmp v3 notify-filter device-traps oid snmpMIBObjects include
set snmp engine-id use-mac-address
set snmp view all oid .1 include
set snmp view all oid system include
set snmp view all oid jnxBoxAnatomy include
set snmp view all oid snmpMIBObjects include'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24884r513320_chk'
  tag severity: 'high'
  tag gid: 'V-223211'
  tag rid: 'SV-223211r513322_rule'
  tag stig_id: 'JUSX-DM-000111'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24872r513321_fix'
  tag 'documentable'
  tag legacy: ['SV-80941', 'V-66451']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
