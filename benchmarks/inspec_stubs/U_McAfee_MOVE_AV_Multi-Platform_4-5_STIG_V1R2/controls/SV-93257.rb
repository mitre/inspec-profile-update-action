control 'SV-93257' do
  title 'The McAfee MOVE AV On Demand Scan policy must be configured to delete files automatically and quarantine as the first response of a threat detection.'
  desc 'Malware incident containment has two major components: stopping the spread of malware and preventing further damage to hosts. Disinfecting a file is generally preferable to quarantining it because the malware is removed and the original file restored; however, many infected files cannot be disinfected. The primary goal of eradication is to remove malware from infected hosts. Deleting files found to contain malware, while also moving them to quarantine, will allow the files to be rendered useless but are recoverable in the event of false positive.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "Actions", verify the "Threat detection first response" is configured for "Delete files automatically and quarantine".

If the "Threat detection first response" is not configured for "Delete files automatically and quarantine", this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "Actions", configure the "Threat detection first response" for "Delete files automatically and quarantine".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78551'
  tag rid: 'SV-93257r1_rule'
  tag stig_id: 'MV45-ODS-000005'
  tag gtitle: 'MV45-ODS-000005'
  tag fix_id: 'F-85287r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
