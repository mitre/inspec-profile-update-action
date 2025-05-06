control 'SV-237326' do
  title 'The ArcGIS Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Review the ArcGIS Server configuration to ensure the application prohibits or restricts the use of PPSM CAL defined ports, protocols, and/or services. Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]admin/security/config (log on when prompted).

Verify the "Protocol" parameter is not set to "HTTP Only".

If the "Protocol" parameter is set to "HTTP Only", this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure the application prohibits or restricts the use of PPSM CAL defined ports, protocols, and/or services. Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]admin/security/config (log on when prompted).
 
Browse to Update. Update the Protocol parameter to "HTTPS Only".

Click "Save"/"Apply".'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40545r642795_chk'
  tag severity: 'medium'
  tag gid: 'V-237326'
  tag rid: 'SV-237326r879588_rule'
  tag stig_id: 'AGIS-00-000055'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-40508r642796_fix'
  tag 'documentable'
  tag legacy: ['SV-79905', 'V-65415']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
