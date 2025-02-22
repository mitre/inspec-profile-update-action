control 'SV-93205' do
  title 'The McAfee MOVE AV SVM Settings policy must be configured to scan for potentially unwanted programs.'
  desc 'Due to the ability of malware to mutate after infection, standard anti-virus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is heuristic detection.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", verify the check box for "Enable scanning for potentially unwanted programs" is selected. 

If the check box for "Enable scanning for potentially unwanted programs" is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", select the check box for "Enable scanning for potentially unwanted programs". 

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78061r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78499'
  tag rid: 'SV-93205r1_rule'
  tag stig_id: 'MV45-SVM-200005'
  tag gtitle: 'MV45-SVM-200005'
  tag fix_id: 'F-85233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
