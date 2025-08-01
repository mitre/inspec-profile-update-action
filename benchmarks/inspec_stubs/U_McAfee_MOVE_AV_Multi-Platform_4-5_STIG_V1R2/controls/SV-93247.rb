control 'SV-93247' do
  title 'The McAfee MOVE AV On Access Scan policy must be configured to delete files automatically and quarantine as the first response of a threat detection.'
  desc 'Malware incident containment has two major components: stopping the spread of malware and preventing further damage to hosts. Disinfecting a file is generally preferable to quarantining it because the malware is removed and the original file restored; however, many infected files cannot be disinfected. The primary goal of eradication is to remove malware from infected hosts.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Click "Actions".

Under "Threat detection first response", verify "Delete files automatically and quarantine" is selected.

If "Threat detection first response" is not set to "Delete files automatically and quarantine", this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured "On Access Scan" policy.

Click "Actions".

Under "Threat detection first response", select "Delete files automatically and quarantine" from the drop-down list.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78541'
  tag rid: 'SV-93247r1_rule'
  tag stig_id: 'MV45-OAS-000009'
  tag gtitle: 'MV45-OAS-000009'
  tag fix_id: 'F-85277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
