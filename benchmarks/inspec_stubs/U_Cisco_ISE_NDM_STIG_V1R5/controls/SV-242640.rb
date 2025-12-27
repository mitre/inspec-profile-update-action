control 'SV-242640' do
  title 'The Cisco ISE must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'If an SNMP stanza does not exist, this is not a finding.

1. Use the command line interface to view the current SNMP configuration.
show startup-config
2. Search for the keyword SNMP.

If versions earlier than SNMPv3 are enabled, this is a finding.

If SNMPv3 is not configured to meet DoD requirements, this is a finding.'
  desc 'fix', 'If SNMP is used by the organization, then SNMP is configured at the command line interface.

To disable SNMPv1 and SNMPv2c if enabled type the remove the group with the following command.

no snmp-server group <community> v1

To enable the SNMPv3 server on Cisco ISE, use the snmp-server enable command in global configuration mode.

1. snmp-server enable
2. snmp-server user <username> v3 hash <auth-password>  <priv-password>
3. snmp-server host {ip-address | hostname} trap version 3 username engine_ID hash <auth-password> <priv-password>'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45915r714228_chk'
  tag severity: 'high'
  tag gid: 'V-242640'
  tag rid: 'SV-242640r879588_rule'
  tag stig_id: 'CSCO-NM-000350'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-45872r714229_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
