control 'SV-79977' do
  title 'The ArcGIS Server must reveal error messages only to the ISSO, ISSM, and SA.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the application. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Review the ArcGIS Server configuration to ensure the application reveals error messages only to authorized personnel. Substitute the target environment’s values for [bracketed] variables. 

1. Inspect the Security Properties of the [C:\\arcgisserver\\logs] folder. Verify that the [ArcGIS Server] account has full control of the folder and only authorized personnel have access to the folder.
 
2. Log on to ArcGIS Server Manager >> Security >> Roles >> Publisher. Verify that only [authorized personnel accounts] are granted this role. 

3. Log on to ArcGIS Server Manager >> Security >> Roles >> Administrator (log on when prompted.) Verify that only [authorized personnel accounts] are granted this role.

Verify any other accounts that have read or other rights to this folder are authorized and documented.

If unauthorized accounts have read or other rights to this folder, this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure the application reveals error messages only to authorized personnel. Substitute the target environment’s values for [bracketed] variables. 

Edit the file system Security Properties of [C:\\arcgisserver\\logs].

Remove unauthorized user accounts and groups.

Do not remove the SYSTEM account, [ArcGIS Server] account, or log agent accounts that support SIEM operations.

Revoke "Publisher" and "Administrator ArcGIS Server" roles from unauthorized accounts.

Log on to ArcGIS Server Manager >> navigate to Security >> Roles >> locate and edit the "Publisher" role.

Remove any unauthorized users from the "Publisher" role.

Log on to ArcGIS Server Manager >> navigate to Security >> Roles >> locate and edit the "Administrator" role.

Remove any unauthorized users from the "Administrator" role.'
  impact 0.5
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66069r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65487'
  tag rid: 'SV-79977r1_rule'
  tag stig_id: 'AGIS-00-000111'
  tag gtitle: 'SRG-APP-000267'
  tag fix_id: 'F-71429r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
