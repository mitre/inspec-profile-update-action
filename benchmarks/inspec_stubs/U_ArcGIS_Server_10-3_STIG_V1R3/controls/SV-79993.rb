control 'SV-79993' do
  title 'The organization must disable organization-defined functions, ports, protocols, and services within the ArcGIS Server deemed to be unnecessary and/or nonsecure.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure that organization-defined unnecessary or insecure ports, functions, and services are disabled. Substitute the target environment’s values for [bracketed] variables.

Using an ArcGIS Server account that is a member of the ArcGIS Server Administrator role, logon to the ArcGIS Server Administrator Directory at https://[server.domain.com:6443]/arcgis/admin.
Browse to “security” >> “config”.
Verify “Protocol” parameter is not set to “HTTP Only”.
If the “Protocol” parameter is set to “HTTP Only”, this is a finding.

This control is not applicable for ArcGIS Servers which are deployed as part of a solution which ensures user web service traffic flows through third-party DoD compliant transport encryption devices (such as a load balancer that supports TLS encryption using DoD-approved certificates.)'
  desc 'fix', 'Configure the ArcGIS Server to ensure organization-defined unnecessary or insecure ports, functions, and services are disabled. Substitute the target environment’s values for [bracketed] variables. 

Navigate to [https://server.domain.com/arcgis]admin/security/config (log on when prompted).
 
Browse to Update. Update the Protocol parameter to "HTTPS Only".

Click "Save"/"Apply".'
  impact 0.5
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66085r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65503'
  tag rid: 'SV-79993r2_rule'
  tag stig_id: 'AGIS-00-000166'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-71445r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
