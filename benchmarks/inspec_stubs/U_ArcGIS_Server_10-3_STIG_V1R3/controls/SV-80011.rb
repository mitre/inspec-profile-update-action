control 'SV-80011' do
  title 'The ArcGIS Server must maintain a separate execution domain for each executing process.'
  desc 'Applications can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is performed in a manner controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.

An example is a web browser with process isolation that provides tabs that are separate processes using separate address spaces to prevent one tab crashing the entire browser.'
  desc 'check', 'Review the ArcGIS Server configuration to ensure all published services maintain a separate execution domain for each process. Substitute the target environment’s values for [bracketed] variables. 

In PowerShell, run the following command, replacing the [bracketed] values with the path of the ArcGIS Server Site "config-store":

Get-ChildItem -recurse [C:\\arcgisserver\\]config-store\\services\\*.json | Select-String -pattern "`"isolationLevel`": `"LOW`""

If any values are returned, this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure all published services maintain a separate execution domain for each process. Substitute the target environment’s values for [bracketed] variables. 

In PowerShell, run the following command, replacing the [bracketed] values with the path of the ArcGIS Server Site "config-store":

Get-ChildItem -recurse [C:\\arcgisserver\\]config-store\\services\\*.json | Select-String -pattern "`"isolationLevel`": `"LOW`""

Stop ArcGIS Server, then replace the "LOW" with "HIGH" in all found files.'
  impact 0.5
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65521'
  tag rid: 'SV-80011r1_rule'
  tag stig_id: 'AGIS-00-000197'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-71463r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
