control 'SV-223272' do
  title 'A secondary SharePoint site collection administrator must be defined when creating a new site collection.'
  desc 'If a site reaches its maximum size, users will be denied access until an administrator fixes the problem. Having a secondary administrator reduces the risk of having a Denial-of-Service on a site. If the site reaches its maximum size, the secondary administrator can fix the problem if the primary administrator is not available. In some situations, having a secondary site administrator could be inappropriate for reasons of control or confidentiality.'
  desc 'check', 'Review the SharePoint server to ensure a secondary site collection administrator is defined when creating a new site collection.

Log on to SharePoint Central Administration as a member of the Farm Administration Group.

Click on "Application Management".

Select "Site Collections" >> Change Site Collections Administrator.

For each Site Collections, review Secondary Site Collection Administrator.

If Secondary Site Collection Administrator is not defined, this is a finding.'
  desc 'fix', 'Configure a secondary SharePoint site collection administrator when creating a new site collection.

Log on to SharePoint Central Administration as a member of the Farm Administration Group.

Click on "Application Management".

Select "Site Collections" >> Change Site Collections Administrator.

For each site, define a Secondary Site Collection Administrator.

Select "OK".'
  impact 0.3
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24945r430873_chk'
  tag severity: 'low'
  tag gid: 'V-223272'
  tag rid: 'SV-223272r612235_rule'
  tag stig_id: 'SP13-00-000185'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24933r430874_fix'
  tag 'documentable'
  tag legacy: ['SV-74437', 'V-60007']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
