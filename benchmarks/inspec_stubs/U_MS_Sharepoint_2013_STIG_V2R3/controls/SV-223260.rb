control 'SV-223260' do
  title 'SharePoint must implement an information system isolation boundary that minimizes the number of nonsecurity functions included within the boundary containing security functions.'
  desc 'The information system isolates security functions from nonsecurity functions by means of an isolation boundary (implemented via partitions and domains) controlling access to and protecting the integrity of, the hardware, software, and firmware that perform those security functions. The information system maintains a separate execution domain (e.g., address space) for each executing process.'
  desc 'check', %q(Review the SharePoint server configuration to ensure an information system isolation boundary that minimizes the number of nonsecurity functions included within the boundary containing security functions are implemented.

Log on to the server that hosts the farm's Central Administration website.

Open IIS Manager.

Expand "Sites" tree view and right-click the web application named "SharePoint Central Administration".

Select "Edit Bindings ...".

Confirm the site is bound to an out-of-band (OOB) IP address.

If the site is bound to a production IP address or not bound to a specific IP address, this is a finding.)
  desc 'fix', %q(Configure the SharePoint server to implement an information system isolation boundary that minimizes the number of nonsecurity functions included within the boundary containing security functions.

Log on to the server that hosts the farm's Central Administration website.

Open IIS Manager.

Expand "Sites" tree view and right-click the web application named "SharePoint Central Administration".

Select "Edit Bindings ...".

Select the site binding record and click "Edit".

From the "IP Address" dropdown list, select an OOB IP address.

Click "Ok".

*NOTE: If the Central Administration site has multiple site bindings, steps will need to be repeated for each site binding.)
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24933r430837_chk'
  tag severity: 'high'
  tag gid: 'V-223260'
  tag rid: 'SV-223260r612235_rule'
  tag stig_id: 'SP13-00-000125'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-24921r430838_fix'
  tag 'documentable'
  tag legacy: ['SV-74411', 'V-59981']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
