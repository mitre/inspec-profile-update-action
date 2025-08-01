control 'SV-79705' do
  title 'The DataPower Gateway providing user authentication intermediary services must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway."
  desc 'check', "Using the appliance's WebGUI, navigate to DataPower Gateway's Configure AAA Policy (authentication, authorization, audit) at Objects >> XML Processing >> AAA Policy. Open the applicable AAA policy. 

On the Identity extraction tab, confirm that the appropriate methods are checked and appropriate processing option specified. 

On the Authentication tab, confirm that all parameters associated with the authentication method (e.g., LDAP) are correctly specified.

If these items are not configured, this is a finding."
  desc 'fix', "Using the appliance's WebGUI, navigate to DataPower Gateway's Configure AAA Policy (authentication, authorization, audit) at Objects >> XML Processing >> AAA Policy. 

Open the applicable AAA policy. 

On the Identity extraction tab, check the appropriate methods and processing option. 

On the Authentication tab, specify all parameters associated with the desired authentication method (e.g., LDAP)."
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65215'
  tag rid: 'SV-79705r1_rule'
  tag stig_id: 'WSDP-AG-000037'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-71155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
