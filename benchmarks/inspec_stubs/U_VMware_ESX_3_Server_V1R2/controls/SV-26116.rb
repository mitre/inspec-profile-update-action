control 'SV-26116' do
  title 'The SNMP service must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy that is provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use that information to launch attacks against the system.'
  desc 'check', "Determine if the system's SNMP service only uses SNMPv3 or its successors.  Consult vendor documentation to determine if earlier versions of SNMP are supported and what configuration is necessary to enable or disable the protocols.  If an earlier version of the protocol is used by the service, this is a finding."
  desc 'fix', "Consult vendor documentation for SNMP configuration procedures.  Configure the system's SNMP service to only use SNMPv3 or its successors."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22447'
  tag rid: 'SV-26116r1_rule'
  tag stig_id: 'GEN005305'
  tag gtitle: 'GEN005305'
  tag fix_id: 'F-26292r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
