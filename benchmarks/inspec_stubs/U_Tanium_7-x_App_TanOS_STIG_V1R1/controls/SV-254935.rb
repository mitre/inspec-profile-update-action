control 'SV-254935' do
  title 'The Tanium application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion.'
  desc 'check', '1. Access the Tanium Server interactively.
 
2. Log on to the TanOS console as the user "tanadmin".

3. Enter "3" to access the "Tanium Support" menu. 

4.  Enter "6" to display last scheduled health check results. 

If none exists, then this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.
 
2. Log on to the TanOS console as the user "tanadmin".

3. Enter "3" to access the "Tanium Support" menu. 

4. Enter "5" to Run a Health Check.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58548r867703_chk'
  tag severity: 'medium'
  tag gid: 'V-254935'
  tag rid: 'SV-254935r867705_rule'
  tag stig_id: 'TANS-AP-000870'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-58492r867704_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
