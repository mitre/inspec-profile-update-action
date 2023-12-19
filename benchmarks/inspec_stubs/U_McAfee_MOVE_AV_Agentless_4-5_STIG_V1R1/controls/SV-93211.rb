control 'SV-93211' do
  title 'The McAfee MOVE AV SVM settings policy must be configured to communicate with the hypervisor/vCenter server via HTTPS protocol.'
  desc 'Requiring the McAfee MOVE AV Agentless SVA to authenticate to the hypervisor over HTTPs ensures the authentication is over a secure path.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "SVM Configuration" (Agentless only), verify the "Protocol" option is set for "HTTPS". 

If the "Protocol" option is not set to "HTTPS", this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "SVM Configuration" (Agentless only), select "HTTPS" for the "Protocol" option.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78067r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78505'
  tag rid: 'SV-93211r1_rule'
  tag stig_id: 'MV45-SVM-200008'
  tag gtitle: 'MV45-SVM-200008'
  tag fix_id: 'F-85239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
