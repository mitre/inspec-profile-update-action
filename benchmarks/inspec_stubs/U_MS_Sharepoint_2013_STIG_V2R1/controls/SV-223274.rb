control 'SV-223274' do
  title 'SharePoint-specific malware (i.e. anti-virus) protection software must be integrated and configured.'
  desc 'Configuring anti-virus settings ensures documents will be scanned for viruses upon download from and upload to the SharePoint server. Anti-virus settings are not configured by default, therefore leaving the documents downloaded from or uploaded to SharePoint open to potential viruses.'
  desc 'check', 'Review the SharePoint server configuration to ensure SharePoint-specific malware (i.e. anti-virus) protection software is integrated and configured.

Log on to Central Administrator.

Navigate to Operations >> Security Configuration.

Select Anti-virus.

If any of the following boxes are unselected, this is a finding:
- Scan documents on upload.
- Scan documents on download.
- Attempt to clean infected documents.'
  desc 'fix', 'Configure and integrate SharePoint-specific malware (i.e. anti-virus) protection software on the SharePoint server.

Install and configure anti-virus package.

Install a SharePoint Server 2010-specific antivirus package. 

Log in to Central Administration.

Navigate to Operations >> Security Configuration.

Select Anti-virus.

Check the following boxes:
- Scan documents on upload.
- Scan documents on download.
- Attempt to clean infected documents.

Select "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24947r430879_chk'
  tag severity: 'medium'
  tag gid: 'V-223274'
  tag rid: 'SV-223274r612235_rule'
  tag stig_id: 'SP13-00-000195'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24935r430880_fix'
  tag 'documentable'
  tag legacy: ['SV-74441', 'V-60011']
  tag cci: ['CCI-000366', 'CCI-001167']
  tag nist: ['CM-6 b', 'SC-18 (2)']
end
