control 'SV-213993' do
  title 'When updates are applied to SQL Server software, any software components that have been replaced or made unnecessary must be removed.'
  desc "Previous versions of DBMS components that are not removed from the information system after updates have been installed may be exploited by adversaries.  
 
Some DBMSs' installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules. 
 
A transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning."
  desc 'check', 'From the server documentation, obtain a listing of required components.  
 
Generate a listing of components installed on the server. 
 
Click Start >> Type "SQL Server 2016 Installation Center" >> Launch the program >> Click Tools >> Click "Installed SQL Server features discovery report" 
 
Compare the feature listing against the required components listing. If any features are installed, but are not required, this is a finding.'
  desc 'fix', 'Remove all features that are not required.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15210r313762_chk'
  tag severity: 'medium'
  tag gid: 'V-213993'
  tag rid: 'SV-213993r879825_rule'
  tag stig_id: 'SQL6-D0-012700'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag fix_id: 'F-15208r313763_fix'
  tag 'documentable'
  tag legacy: ['SV-93953', 'V-79247']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
