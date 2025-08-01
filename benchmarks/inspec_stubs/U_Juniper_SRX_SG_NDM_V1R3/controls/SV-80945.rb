control 'SV-80945' do
  title 'For nonlocal maintenance sessions using SNMP, the Juniper SRX Services Gateway must securely configure SNMPv3 with privacy options to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 
 
To protect the confidentiality of nonlocal maintenance sessions, SNMPv3 with AES encryption to must be configured to provide confidentiality. The Juniper SRX allows the use of SNMPv3 to monitor or query the device in support of diagnostics information. SNMP cannot be used to make configuration changes; however, it is a valuable diagnostic tool. SNMP is disabled by default and must be enabled for use. SNMPv3 is the DoD-required version, but must be configured to be used securely.'
  desc 'check', 'Verify SNMPv3 is configured with privacy options.

[edit]
show snmp v3
 
If SNMPv3, AES encryption, and other privacy options are not configured, this is a finding.'
  desc 'fix', 'Configure SNMP to use version 3 with privacy options. The following is an example.

[edit]
set snmp location <NAME>
set snmp v3 usm local-engine user <NAME> privacy-AES128
set snmp v3 vacm security-to-group security-model usm security-name <NAME> group <NAMEGROUP>
set snmp v3 vacm access group <NAME-GROUP> default-context-prefix security-model usm
security-level privacy read-view all
set snmp v3 vacm access group <NAME-GROUP> default-context-prefix security-model usm
security-level privacy notify-view all'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67101r1_chk'
  tag severity: 'high'
  tag gid: 'V-66455'
  tag rid: 'SV-80945r1_rule'
  tag stig_id: 'JUSX-DM-000149'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-72531r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
