control 'SV-256436' do
  title 'The ESXi host must enable audit logging.'
  desc 'ESXi offers both local and remote audit recordkeeping to meet the requirements of the NIAP Virtualization Protection Profile and Server Virtualization Extended Package. Local records are stored on any accessible local or VMFS path. Remote records are sent to the global syslog servers configured elsewhere.

To operate in the NIAP validated state, ESXi must enable and properly configure this audit system. This system is disabled by default.

Note: Audit records can be viewed locally via the "/bin/auditLogReader" utility over SSH or at the ESXi shell.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli system auditrecords get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.auditrecords.get.invoke()|Format-List

Example result:

AuditRecordRemoteTransmissionActive : true
AuditRecordStorageActive : true
AuditRecordStorageCapacity : 100
AuditRecordStorageDirectory : /scratch/auditLog

Note: The "Audit Record Storage Directory" may differ from the default above, but it must still be located on persistent storage.

If audit record storage is not active and configured, this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following commands:

Optional: Set the audit log location to persistent storage. This is set to "/scratch/auditLog" by default and does not normally need to be changed.

# esxcli system auditrecords local set --directory="/full/path/here"

Mandatory:

# esxcli system auditrecords local set --size=100
# esxcli system auditrecords local enable
# esxcli system auditrecords remote enable
# esxcli system syslog reload

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.auditrecords.local.set.CreateArgs()
*Optional* $arguments.directory = "/full/path/here"
$arguments.size="100"
$esxcli.system.auditrecords.local.set.Invoke($arguments)
$esxcli.system.auditrecords.local.enable.Invoke()
$esxcli.system.auditrecords.remote.enable.Invoke()'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60111r919015_chk'
  tag severity: 'medium'
  tag gid: 'V-256436'
  tag rid: 'SV-256436r919017_rule'
  tag stig_id: 'ESXI-70-000084'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60054r919016_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
