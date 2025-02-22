control 'SV-93197' do
  title 'The McAfee MOVE AV Options policy must specify the location of the quarantine network share.'
  desc 'The quarantine on each system represents a potential danger should the files contained within the quarantine be executed inadvertently.

To centrally manage the quarantine on all systems, the quarantine should always be configured the same across all systems, which will allow management to better control access to those locations.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager" (Agentless only), verify the "Quarantine network share" is populated.

If the "Quarantine network share" is not populated, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager" (Agentless only), populate the "Quarantine network share" field with a valid location for storing the quarantine.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78053r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78491'
  tag rid: 'SV-93197r1_rule'
  tag stig_id: 'MV45-OPT-200001'
  tag gtitle: 'MV45-OPT-200001'
  tag fix_id: 'F-85225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
