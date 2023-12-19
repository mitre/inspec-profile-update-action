control 'SV-93199' do
  title 'The McAfee MOVE AV Options policy must specify the username and password for the quarantine network share.'
  desc 'The quarantine on each system represents a potential danger should the files contained within the quarantine be executed inadvertently. 

To centrally manage the quarantine on all systems, the quarantine should always be configured the same across all systems, which will allow management to better control access to those locations.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager" (Agentless only), verify the "Network domain and username", "Network password", and "Confirm password" fields are populated. The "Network password" and "Confirm password" will be masked if populated.

If the "Network domain and username", "Network password", and "Confirm password" fields are not populated, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager" (Agentless only), configure the quarantine with “Network domain and username" and "Network password" for accessing the quarantine network share.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78493'
  tag rid: 'SV-93199r1_rule'
  tag stig_id: 'MV45-OPT-200002'
  tag gtitle: 'MV45-OPT-200002'
  tag fix_id: 'F-85227r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
