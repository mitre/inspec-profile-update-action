control 'SV-256414' do
  title 'Simple Network Management Protocol (SNMP) must be configured properly on the ESXi host.'
  desc 'If SNMP is not being used, it must remain disabled. If it is being used, the proper trap destination must be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can use this information to plan an attack.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli system snmp get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHostSnmp | Select *

If SNMP is not in use and is enabled, this is a finding.

If SNMP is enabled and read-only communities are set to "public", this is a finding.

If SNMP is enabled and is not using v3 targets, this is a finding.

Note: SNMP v3 targets can only be viewed and configured via the "esxcli" command.'
  desc 'fix', 'To disable SNMP from an ESXi shell, run the following command:

# esxcli system snmp set -e no

or

From a PowerCLI command prompt while connected to the ESXi Host:

Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false

To configure SNMP for v3 targets, use the "esxcli system snmp set" command set locally on the host or remotely via PowerCLI.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60089r886021_chk'
  tag severity: 'medium'
  tag gid: 'V-256414'
  tag rid: 'SV-256414r886023_rule'
  tag stig_id: 'ESXI-70-000053'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60032r886022_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
