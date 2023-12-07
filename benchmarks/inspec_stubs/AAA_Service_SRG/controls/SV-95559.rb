control 'SV-95559' do
  title 'AAA Services must be configured to use Role-Based Access Control (RBAC) policy for levels of access authorization.'
  desc 'RBAC is an access control policy that restricts information system access to authorized users. Without these security policies, access control and enforcement mechanisms will not prevent unauthorized access.

Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When users are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every user (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.'
  desc 'check', 'Verify AAA Services are configured to use RBAC policy for levels of access authorization. Confirm the RBAC groups have tiered privileges, and users are in the appropriate groups. In the following TACACS+ example the user (test-user) is a member of the group “test-group”.

<CSUserver>$/opt/ciscosecure/CLI/ViewProfile -p 9900 -u user-test
User Profile Information
user = test-user{
profile_id = 66
profile_cycle = 1
member = test-group
password = des "********"
}

Below is an example of CiscoSecure TACACS+ server defining the privilege level.
user = test-user{
 password = clear "xxxxx"
 service = shell {
 set priv-lvl = 7
 }
}

If AAA Services are not configured to use RBAC policy for levels of access authorization, this is a finding.'
  desc 'fix', 'Configure AAA Services to use RBAC policy for levels of access authorization. Configure AAA Services with standard accounts and assign them to privilege levels that meet their job description.'
  impact 0.3
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80585r2_chk'
  tag severity: 'low'
  tag gid: 'V-80849'
  tag rid: 'SV-95559r1_rule'
  tag stig_id: 'SRG-APP-000329-AAA-000190'
  tag gtitle: 'SRG-APP-000329-AAA-000190'
  tag fix_id: 'F-87703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002169']
  tag nist: ['AC-3 (7)']
end
