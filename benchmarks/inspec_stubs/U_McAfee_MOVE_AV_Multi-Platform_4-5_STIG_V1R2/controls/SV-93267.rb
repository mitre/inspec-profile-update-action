control 'SV-93267' do
  title 'The McAfee MOVE AV Options Policy must be configured to automatically delete quarantined data after a time period of no more than 28 days.'
  desc "The quarantine on each system represents a potential danger should the files contained within the quarantine be executed inadvertently. Deleting the quarantine contents on a regular basis will alleviate the ability of malware from being executed. An organization's incident response policy should also contain steps in removing quarantined items after their forensic value has been depleted."
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager", verify the value for "Specify the maximum number of days to keep quarantine data" is set to "28" days or less.

If the value for "Specify the maximum number of days to keep quarantine data" is not set to "28" days or less, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager", set the value for "Specify the maximum number of days to keep quarantine data" to "28" days or less.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78561'
  tag rid: 'SV-93267r1_rule'
  tag stig_id: 'MV45-OPT-000002'
  tag gtitle: 'MV45-OPT-000002'
  tag fix_id: 'F-85297r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
