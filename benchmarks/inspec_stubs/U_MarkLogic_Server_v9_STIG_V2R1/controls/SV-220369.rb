control 'SV-220369' do
  title 'MarkLogic Server must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. 

Accordingly, a risk assessment is used in determining the authentication needs of the organization. 

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', 'Review MarkLogic settings to determine if non-organizational users are uniquely identified and authenticated.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users; if there is a non-organizational user who is not uniquely identified, this is a finding.'
  desc 'fix', 'If non-organizational users are not uniquely identified and authenticated, implement the steps below.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users, and remove any non-organizational users who are not uniquely identified.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22084r531256_chk'
  tag severity: 'medium'
  tag gid: 'V-220369'
  tag rid: 'SV-220369r622777_rule'
  tag stig_id: 'ML09-00-004400'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-22073r401559_fix'
  tag 'documentable'
  tag legacy: ['SV-110087', 'V-100983']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
