control 'SV-93279' do
  title 'The McAfee MOVE AV SVM Settings policy must be configured to scan for Multipurpose Internet Mail Extensions (MIME)-encoded files.'
  desc 'Multipurpose Internet Mail Extensions (MIME) encoded files can be crafted to hide a malicious payload. When the MIME encoded file is presented to software that decodes the MIME encoded files, such as an email client, the malware is released. Scanning these files as part of the regularly scheduled scans tasks will mitigate this risk.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", verify the "Enabled scanning for MIME-encoded files" check box is selected.

If the "Enabled scanning for MIME-encoded files" is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "Scanning Options", select the "Enabled scanning for MIME-encoded files" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78143r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78573'
  tag rid: 'SV-93279r1_rule'
  tag stig_id: 'MV45-SVM-000006'
  tag gtitle: 'MV45-SVM-000006'
  tag fix_id: 'F-85309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
