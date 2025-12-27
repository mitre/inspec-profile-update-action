control 'SV-218771' do
  title 'The IIS 10.0 website must have a unique application pool.'
  desc 'Application pools isolate sites and applications to address reliability, availability, and security issues. Sites and applications may be grouped according to configurations, although each site will be associated with a unique application pool.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 10.0 Manager.

Click "Application Pools".

In the list of Application Pools, review the "Applications" column and verify unique application pools for each website.

If any Application Pools are being used for more than one website, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the site name under review.

Assign a unique application pool to each website.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20244r311211_chk'
  tag severity: 'medium'
  tag gid: 'V-218771'
  tag rid: 'SV-218771r879887_rule'
  tag stig_id: 'IIST-SI-000251'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20242r311212_fix'
  tag 'documentable'
  tag legacy: ['SV-109367', 'V-100263']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
