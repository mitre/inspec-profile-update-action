control 'SV-93437' do
  title 'The Tanium documentation identifying recognized and trusted folders for IOC Detect Folder streams must be maintained.'
  desc 'An IOC stream is a series or "stream" of IOCs that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. IOC Detect can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of folder maintainers for IOC Detect Folder streams.

If the site does not leverage Folder streams to import IOCs, this finding is "Not Applicable".

If the site does use Folder streams to import IOCs and the folder maintainers are not documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium IOC Folder stream maintainers.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78307r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78731'
  tag rid: 'SV-93437r1_rule'
  tag stig_id: 'TANS-SV-000048'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-85473r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
