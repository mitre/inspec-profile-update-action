control 'SV-237325' do
  title 'The ArcGIS Server must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', 'Review the ArcGIS Server configuration to ensure that non-essential capabilities are disabled. Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]admin/system/handlers/rest/servicesdirectory (log on when prompted).

Verify that the "Services Directory" property is set to "Disabled".

If the "Services Directory" property is set to "Enabled", this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure non-essential capabilities are disabled. Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]admin/system/handlers/rest/servicesdirectory (log on when prompted).

Uncheck the value for "Services Directory Enabled". Click "Save".'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40544r642792_chk'
  tag severity: 'medium'
  tag gid: 'V-237325'
  tag rid: 'SV-237325r879587_rule'
  tag stig_id: 'AGIS-00-000054'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-40507r642793_fix'
  tag 'documentable'
  tag legacy: ['SV-79903', 'V-65413']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
