control 'SV-255324' do
  title 'The Azure SQL Database must be configured to generate audit records for DOD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within Azure SQL Database (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DOD has defined the list of events for which Azure SQL Database will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', 'Check Azure SQL Database to see if an auditing is enabled.

Execute the following steps: 
1. In the Azure Portal, open a Cloud Shell session.
2. Run this PowerShell command to determine if SQL Auditing is enabled:

$ResourceGroup = "myResourceGroup"
$ServerName = "myServerName"
Get-AzSqlServerAudit -ResourceGroupName $ResourceGroup -ServerName $ServerName `
| Select-object -property BlobStorageTargetState,LogAnalyticsTargetState,EventHubTargetState

If BlobStorageTargetState, LogAnalyticsTargetState and EventHubTargetState (all three) are Disabled, this is a finding.'
  desc 'fix', 'Deploy an Azure SQL Database audit.

Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58997r871096_chk'
  tag severity: 'medium'
  tag gid: 'V-255324'
  tag rid: 'SV-255324r877276_rule'
  tag stig_id: 'ASQL-00-004300'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-58941r877276_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
