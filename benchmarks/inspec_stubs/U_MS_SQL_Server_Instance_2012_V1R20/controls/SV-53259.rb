control 'SV-53259' do
  title 'The system must activate an alarm and/or automatically shut SQL Server down if a failure is detected in its software components.'
  desc 'Predictable failure prevention requires organizational planning to address system failure issues. If components key to maintaining system security fail to function, then SQL Server could continue operating in an unsecure state. The organization must be prepared, and the system must be configured, to send an alarm for such conditions and/or automatically shut SQL Server down.

If appropriate actions are not taken when component failures occur, a denial of service condition may occur. Appropriate actions can include conducting a graceful application shutdown to avoid losing information.

For the purposes of this requirement, "component" may be interpreted as meaning any of the Windows services that comprise a SQL Server instance.  "The system" encompasses SQL Server itself, the Windows operating system, and any monitoring/management tools used to control the server.'
  desc 'check', 'Check the configuration of SQL Server, the operating system and any monitoring/management tools to verify the system activates an alarm and/or triggers a shutdown of SQL Server when a component failure is detected.

If system does not take either or both actions, this is a finding.'
  desc 'fix', 'Configure the system to activate an alarm and/or trigger a SQL Server shutdown when a component failure is detected.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47560r6_chk'
  tag severity: 'medium'
  tag gid: 'V-40905'
  tag rid: 'SV-53259r5_rule'
  tag stig_id: 'SQL2-00-023000'
  tag gtitle: 'SRG-APP-000268-DB-000164'
  tag fix_id: 'F-46187r4_fix'
  tag cci: ['CCI-001328']
  tag nist: ['SI-13 (4) (b)']
end
