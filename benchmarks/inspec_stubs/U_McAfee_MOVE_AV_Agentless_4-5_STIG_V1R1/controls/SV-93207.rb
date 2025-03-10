control 'SV-93207' do
  title 'The McAfee MOVE AV SVM Settings policy must be configured to scan for Multipurpose Internet Mail Extensions (MIME)-encoded files.'
  desc 'MIME-encoded files can be crafted to hide a malicious payload. When the MIME-encoded file is presented to software that decodes the MIME encoded files, such as an email client, the malware is released. Scanning these files as part of the regularly scheduled scans tasks will mitigate this risk.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", verify "Enabled scanning for MIME-encoded files" check box is selected.

If "Enabled scanning for MIME-encoded files" is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", select the "Enabled scanning for MIME-encoded files" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78063r3_chk'
  tag severity: 'medium'
  tag gid: 'V-78501'
  tag rid: 'SV-93207r1_rule'
  tag stig_id: 'MV45-SVM-200006'
  tag gtitle: 'MV45-SVM-200006'
  tag fix_id: 'F-85235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
