control 'SV-82363' do
  title 'SQL Server must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Non-organizational users shall be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

This may be accomplished by a code embedded within the userid, or via a flag or code column in a table of users, or by some other means. In any case, the user must be individually identified to, and within, SQL Server via a mapping to an individual account and not mapping to a shared account.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, and other organizations.'
  desc 'check', 'Review documentation, SQL Server settings and authentication system settings to determine if non-organizational users are individually identified and authenticated when logging onto the system.

If the documentation indicates that this is a public-facing, read-only (from the point of view of public users) database that does not require individual authentication, this is not a finding.

If non-organizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Configure SQL Server to uniquely identify and authenticate all non-organizational users who log onto the system. This likely would be done via a combination of the operating system with unique accounts and the SQL Server by ensuring mapping to individual accounts.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68441r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67873'
  tag rid: 'SV-82363r1_rule'
  tag stig_id: 'SQL4-00-018900'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-73989r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
