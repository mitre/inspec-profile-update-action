control 'SV-79707' do
  title 'The DataPower Gateway providing user access control intermediary services must be configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or AAA server) which validate user account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the gateway resides on the untrusted zone of the Enclave.'
  desc 'check', "Using the appliance's WebGUI, navigate to DataPower Gateway's Configure AAA Policy (authentication, authorization, audit) at Objects >> XML Processing >> AAA Policy. 

On the Resource extraction tab, confirm that the correct resource information categories are checked. 

If these items are not configured, this is a finding."
  desc 'fix', "Using the appliance's WebGUI, navigate to DataPower Gateway's Configure AAA Policy (authentication, authorization, audit) at Objects >> XML Processing >> AAA Policy. 

On the Resource extraction tab, specify the correct resource information categories. 

If there is a requirement for resource mapping, on the Resource mapping tab, specify the appropriate method and associated information. 

On the Authorization tab, specify the correct methods, associated information and caching parameters."
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65217'
  tag rid: 'SV-79707r1_rule'
  tag stig_id: 'WSDP-AG-000038'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-71157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
