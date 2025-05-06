control 'SV-85977' do
  title 'The CA API Gateway providing user authentication intermediary services must restrict user authentication traffic to specific authentication server(s).'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ALG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

The CA API Gateway must be configured to direct authentication traffic to specific authentication servers/URLs."
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select the "Identity Providers" tab, right-click a Registered Identity Provider, such as an LDAP Identity Provider, and select "Properties". 

Verify that a list of "LDAP Host URLs" is provided for use in authentication against this provider. 

If all of the servers needed for authentication are not listed in accordance with organizational requirements, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Select the "Identity Providers" tab, right-click a Registered Identity Provider such as an LDAP Identity Provider, and select "Properties".

Add the additional "LDAP Host URLs" to the list in accordance with organizational requirements and click "Finish".'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71353'
  tag rid: 'SV-85977r1_rule'
  tag stig_id: 'CAGW-GW-000320'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-77663r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
