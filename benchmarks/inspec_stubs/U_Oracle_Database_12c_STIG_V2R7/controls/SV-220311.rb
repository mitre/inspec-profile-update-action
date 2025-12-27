control 'SV-220311' do
  title 'The DBMS must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Non-organizational users shall be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', 'Review DBMS settings to determine whether non-organizational users are uniquely identified and authenticated when logging onto the system.

If non-organizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Configure DBMS settings to uniquely identify and authenticate all non-organizational users who log onto the system.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22026r392064_chk'
  tag severity: 'medium'
  tag gid: 'V-220311'
  tag rid: 'SV-220311r879617_rule'
  tag stig_id: 'O121-P2-015800'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-22018r392065_fix'
  tag 'documentable'
  tag legacy: ['SV-76371', 'V-61881']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
