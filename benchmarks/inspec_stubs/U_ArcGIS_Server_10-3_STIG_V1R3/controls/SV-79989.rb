control 'SV-79989' do
  title 'The ArcGIS Server must enforce access restrictions associated with changes to application configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure that the application enforces access restrictions associated with changes to application configuration. Substitute the target environment’s values for [bracketed] variables.

Logon to ArcGIS Server Manager ([https://server.domain.com/arcgis]/manager]) (logon when prompted) >> “Security” >> “Roles” >> “Administrator” role.

Verify that only authorized personnel are listed as members of the “Administrator” role. 

If unauthorized personnel are members of the “Administrator” role, this is a finding.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD compliant certificate authentication solutions.'
  desc 'fix', 'Configure the ArcGIS Server to enforce access restrictions associated with changes to application configuration. Substitute the target environment’s values for [bracketed] variables. 

Log on to ArcGIS Server Manager ([https://server.domain.com/arcgis]/manager]) (log on when prompted) >> Security >> Roles >> "Administrator" role.

Remove unauthorized personnel from the "Administrator" role.'
  impact 0.5
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66081r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65499'
  tag rid: 'SV-79989r2_rule'
  tag stig_id: 'AGIS-00-000164'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-71441r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
