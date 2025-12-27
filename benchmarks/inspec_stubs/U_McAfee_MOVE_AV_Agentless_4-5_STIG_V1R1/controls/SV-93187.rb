control 'SV-93187' do
  title 'The McAfee MOVE AntiVirus On Demand Scan policy must be configured to stop an on-demand scan after 150 minutes.'
  desc 'This setting configures the maximum time (in minutes) for on-demand scanning. The default setting is 150 minutes. Typically, file scans are very fast. However, file scans may take longer due to large file size, file type, or heavy load on the Security Virtual Machine (SVM). For cases where an on-demand scan will take longer, the organization should determine the maximum amount of time for its on-demand scanning and explicitly configure this setting.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", verify "On-demand scan will stop after" is configured for 150 minutes or less.

If "On-demand scan will stop after" is not configured for 150 minutes or less, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Demand Scan".

Select each configured On Demand Scan policy.

Click "Show Advanced".

Under "On-demand Scan", configure "On-demand scan will stop after" for 150 minutes or less.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78043r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78481'
  tag rid: 'SV-93187r1_rule'
  tag stig_id: 'MV45-ODS-200003'
  tag gtitle: 'MV45-ODS-200003'
  tag fix_id: 'F-85215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
