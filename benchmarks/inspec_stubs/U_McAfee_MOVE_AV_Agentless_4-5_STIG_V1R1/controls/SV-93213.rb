control 'SV-93213' do
  title 'The McAfee MOVE AV SVM settings policy must be configured to authenticate to the hypervisor/vCenter server with user name and password.'
  desc 'Requiring the McAfee MOVE AV Agentless SVA to authenticate to the hypervisor with a username and password, coupled with HTTPs, ensures authentication is over a secure path from a valid source.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "SVM Configuration" (Agentless only), verify the "Username:" field is populated. 

Note: The "Password:" field will appear to be blank. Since the "Username:" field cannot be populated and saved without a password, the "Password:" field requirement can be considered compliant provided the "Username:" field is validated as populated. 

If the "Username:" field is not populated, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "SVM Configuration" (Agentless only), populate the "Username:" and "Password:" fields with a user/password combination that has authentication access to the hypervisor. 

Click "Test connection settings". 

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78069r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78507'
  tag rid: 'SV-93213r1_rule'
  tag stig_id: 'MV45-SVM-200009'
  tag gtitle: 'MV45-SVM-200009'
  tag fix_id: 'F-85241r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
