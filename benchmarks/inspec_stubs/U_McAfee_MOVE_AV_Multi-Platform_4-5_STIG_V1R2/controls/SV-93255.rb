control 'SV-93255' do
  title 'The McAfee MOVE AV On Demand Scan policy must be configured to cache scan results for files smaller than 40 MB.'
  desc 'This setting configures the maximum file size (in MB) up to which scan results should be cached. The default setting is 40 MB. Files smaller than this threshold are copied completely to the Security Virtual Machine (SVM) and scanned. If the file is found to be clean, its scan result is cached based on its SHA 1 checksum for faster future access. Files larger than this size threshold are transferred in chunks that are requested by the SVM and scanned. Setting that threshold higher could impact the performance of the scan processes.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", verify "Cache scan results for files smaller than" is configured for 40 MB or smaller.

If "Cache scan results for files smaller than" is not configured for 40 MB or smaller, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", configure "Cache scan results for files smaller than" for 40 MB or smaller.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78119r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78549'
  tag rid: 'SV-93255r1_rule'
  tag stig_id: 'MV45-ODS-000004'
  tag gtitle: 'MV45-ODS-000004'
  tag fix_id: 'F-85285r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
