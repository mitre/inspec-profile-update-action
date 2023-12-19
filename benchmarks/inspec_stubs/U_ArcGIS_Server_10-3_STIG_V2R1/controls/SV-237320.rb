control 'SV-237320' do
  title 'The ArcGIS Server must protect the integrity of remote access sessions by enabling HTTPS with DoD-approved certificates.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure the application implements cryptographic mechanisms to protect the integrity of remote access sessions. Substitute the target environment’s values for [bracketed] variables.

Navigate to IIS Manager >> [Default Website] >> Open “Bindings...”
Verify “https” is listed as a binding.
If “https” is not identified as a binding, this is a finding.

Navigate to IIS Manager >> [Default Website] >> “SSL Settings”
Verify that “Require SSL” is checked.
If “Require SSL” is not checked, this is a finding.

This control is not applicable for ArcGIS Servers which are deployed as part of a solution which ensures user web service traffic flows through third-party DoD compliant transport encryption devices (such as a load balancer that supports TLS encryption using DoD-approved certificates.)

This control is not applicable for ArcGIS Servers which are not deployed with the ArcGIS Web Adaptor component.'
  desc 'fix', 'Configure the ArcGIS Server to ensure the application implements cryptographic mechanisms to protect the integrity of remote access sessions. Substitute the target environment’s values for [bracketed] variables. 

Navigate to IIS Manager >> [Default Website] >> Open "Bindings...". Click "Add..."

Under "Type:", select "https". Select an organizationally approved SSL certificate to associate with the https binding. (If no SSL Certificate is available, refer to http://technet.microsoft.com/en-us/library/cc731977(v=ws.10).aspx for guidance on requesting and installing an Internet Server Certificate [IIS 7]).

Navigate to IIS Manager >> [Default Website] >> SSL Settings. Check "Require SSL".'
  impact 0.7
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40539r642777_chk'
  tag severity: 'high'
  tag gid: 'V-237320'
  tag rid: 'SV-237320r879520_rule'
  tag stig_id: 'AGIS-00-000007'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-40502r642778_fix'
  tag 'documentable'
  tag legacy: ['SV-79809', 'V-65319']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
