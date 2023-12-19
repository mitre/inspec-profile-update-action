control 'SV-93277' do
  title 'The McAfee MOVE AV SVM Settings policy must be configured to scan for potentially unwanted programs.'
  desc 'Due to the ability of malware to mutate after infection, standard anti-virus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is heuristic detection.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", verify the "Enable scanning for potentially unwanted programs" check box is selected. 

If the check box for "Enable scanning for potentially unwanted programs" is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", select the "Enable scanning for potentially unwanted programs" check box. 

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78141r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78571'
  tag rid: 'SV-93277r1_rule'
  tag stig_id: 'MV45-SVM-000005'
  tag gtitle: 'MV45-SVM-000005'
  tag fix_id: 'F-85307r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
