control 'SV-213975' do
  title 'SQL Server must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.'
  desc 'check', %q(Review system documentation to determine if Common Criteria Compliance is not required due to potential impact on system performance. 

SQL Server Residual Information Protection (RIP) requires a memory allocation to be overwritten with a known pattern of bits before memory is reallocated to a new resource. Meeting the RIP standard can contribute to improved security; however, overwriting the memory allocation can slow performance. After the common criteria compliance enabled option is enabled, the overwriting occurs. 

Review the Instance configuration: 


SELECT value_in_use
FROM sys.configurations
WHERE name = 'common criteria compliance enabled'

If "value_in_use" is set to "1" this is not a finding.
If "value_in_use" is set to "0" this is a finding. 

NOTE: Enabling this feature may impact performance on highly active SQL Server instances. If an exception justifying setting SQL Server Residual Information Protection (RIP) to disabled (value_in_use set to "0") has been documented and approved, then this may be downgraded to a CAT III finding.)
  desc 'fix', "Configure SQL Server to effectively protect the private resources of one process or user from unauthorized access by another user or process. 
 
sp_configure 'show advanced options', 1;   
GO   
RECONFIGURE;   
GO   
sp_configure 'common criteria compliance enabled', 1;   
GO   
RECONFIGURE   
GO"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15192r313708_chk'
  tag severity: 'medium'
  tag gid: 'V-213975'
  tag rid: 'SV-213975r879649_rule'
  tag stig_id: 'SQL6-D0-009800'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-15190r313709_fix'
  tag 'documentable'
  tag legacy: ['SV-93917', 'V-79211']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
