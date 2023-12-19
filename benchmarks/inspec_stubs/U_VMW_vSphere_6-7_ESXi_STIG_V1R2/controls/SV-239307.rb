control 'SV-239307' do
  title 'SNMP must be configured properly on the ESXi host.'
  desc 'If SNMP is not being used, it must remain disabled. If it is being used, the proper trap destination must be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can then use this information to plan an attack.'
  desc 'check', 'From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHostSnmp | Select *

or

From an console or ssh session, run the follow command:

esxcli system snmp get

If SNMP is not in use and is enabled, this is a finding.

If SNMP is enabled and read-only communities is set to "public", this is a finding.

If SNMP is enabled and is not using v3 targets, this is a finding.

Note: SNMP v3 targets can only be viewed and configured from the esxcli command.'
  desc 'fix', 'To disable SNMP, run the following command from a PowerCLI command prompt while connected to the ESXi Host:

Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false

or

From a console or ssh session, run the follow command:

esxcli system snmp set -e no

To configure SNMP for v3 targets, use the "esxcli system snmp set" command set.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42540r674848_chk'
  tag severity: 'medium'
  tag gid: 'V-239307'
  tag rid: 'SV-239307r674850_rule'
  tag stig_id: 'ESXI-67-000053'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42499r674849_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
