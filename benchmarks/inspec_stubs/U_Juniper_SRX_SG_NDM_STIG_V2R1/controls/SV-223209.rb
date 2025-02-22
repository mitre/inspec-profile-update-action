control 'SV-223209' do
  title 'For nonlocal maintenance sessions, the Juniper SRX Services Gateway must remove or explicitly deny the use of nonsecure protocols.'
  desc 'If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Tools used for nonlocal management and diagnostics with the Juniper SRX include SSH but may also include compatible enterprise maintenance and diagnostics servers. Regardless of the tool used, the Juniper SRX must permit only the use of protocols with the capability to be configured securely with integrity protections. Specifically, use SSH instead of Telnet, SCP instead of FTP, and SNMPv3 rather than other versions SNMP.'
  desc 'check', 'Verify nonsecure protocols are not enabled for management access by viewing the enabled system services.

From the operational hierarchy:

> show config | match "set system services" | display set 

From the configuration hierarchy:

[edit]
show snmp
show system services telnet
show system services ftp
show system services ssh

If nonsecure protocols and protocol versions such as Telnet, FTP, SNMPv1, SNMPv2c, or SSHv1 are enabled, this is a finding.'
  desc 'fix', 'Remove or deny nonsecure protocols to prevent their usage for nonlocal management and diagnostic communications.

Use the delete command to disable services that should not be enabled.

Example deletion commands:

[edit]
delete system services telnet
delete system services ftp
delete snmp v1
delete snmp v2c
delete set system services ssh protocol-version v1'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24882r513314_chk'
  tag severity: 'medium'
  tag gid: 'V-223209'
  tag rid: 'SV-223209r513316_rule'
  tag stig_id: 'JUSX-DM-000109'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24870r513315_fix'
  tag 'documentable'
  tag legacy: ['SV-80989', 'V-66499']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
