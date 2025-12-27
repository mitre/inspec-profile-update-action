control 'SV-218744' do
  title 'Mappings to unused and vulnerable scripts on the IIS 10.0 website must be removed.'
  desc 'IIS 10.0 will either allow or deny script execution based on file extension. The ability to control script execution is controlled through two features with IIS 10.0, Request Filtering and Handler Mappings.

For Handler Mappings, the ISSO must document and approve all allowable file extensions the website allows (white list) and denies (black list). The white list and black list will be compared to the Handler Mappings in IIS 8. Handler Mappings at the site level take precedence over Handler Mappings at the server level.'
  desc 'check', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

For Handler Mappings, the ISSO must document and approve all allowable scripts the website allows (white list) and denies (black list). The white list and black list will be compared to the Handler Mappings in IIS 10.0. Handler Mappings at the site level take precedence over Handler Mappings at the server level.

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click "Handler Mappings".

If any script file extensions from the black list are enabled, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the site name under review.

Double-click "Handler Mappings".

Remove any script file extensions listed on the black list that are enabled.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20217r903112_chk'
  tag severity: 'medium'
  tag gid: 'V-218744'
  tag rid: 'SV-218744r903113_rule'
  tag stig_id: 'IIST-SI-000215'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-20215r311131_fix'
  tag 'documentable'
  tag legacy: ['SV-109313', 'V-100209']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
