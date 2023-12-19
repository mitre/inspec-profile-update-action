control 'SV-235982' do
  title 'Oracle WebLogic must protect the integrity and availability of publicly available information and applications.'
  desc 'The purpose of this control is to ensure organizations explicitly address the protection needs for public information and applications, with such protection likely being implemented as part of other security controls.

Application servers must protect the integrity of publicly available information.'
  desc 'check', "1. Access AC 
2. From 'Domain Structure', select 'Deployments' 
3. Select a deployed component which contains publicly available information and/or applications
4. Select 'Targets' tab
5. Ensure one or more of the selected targets for this deployment is a cluster of managed servers

If the information requires clustering of managed server and the managed servers are not clustered, this is a finding."
  desc 'fix', "1. Access AC 
2. From 'Domain Structure', select 'Deployments' 
3. Select a deployed component which contains publicly available information and/or applications
4. Utilize 'Change Center' to create a new change session
5. Select 'Targets' tab
6. Select one or more clusters of managed servers as a target for this deployment. Click 'Save'."
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39201r628722_chk'
  tag severity: 'medium'
  tag gid: 'V-235982'
  tag rid: 'SV-235982r628724_rule'
  tag stig_id: 'WBLC-08-000218'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag fix_id: 'F-39164r628723_fix'
  tag 'documentable'
  tag legacy: ['SV-70569', 'V-56315']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
