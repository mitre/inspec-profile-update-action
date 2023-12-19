control 'SV-86059' do
  title 'The CA API Gateway must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If the cached authenticator information is out of date, the validity of the authentication information may be questionable.

This requirement applies to all ALGs that may cache user authenticators for use throughout a session. This requirement also applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).

The CA API Gateway must be configured to use an organization-defined value for determining the expiration of cached data from an identity provider or third party, such as a SAML Token Service.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and select the "Identity Provider" tab. 

Verify the "Cache Size" and "Cache Maximum Age" are set in accordance with organization-defined requirements. 

If the values are not set or are not set in accordance with organizational requirements, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and select the "Identity Provider" tab. 

Update the "Cache Size" and "Cache Maximum Age" in accordance with organization-defined requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71435'
  tag rid: 'SV-86059r1_rule'
  tag stig_id: 'CAGW-GW-000630'
  tag gtitle: 'SRG-NET-000344-ALG-000098'
  tag fix_id: 'F-77753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
