control 'SV-221623' do
  title 'Splunk Enterprise must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to be assigned to the Power User role.'
  desc "Without restricting which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'If using LDAP:
Select Settings >> Access Controls >> Authentication Method >> LDAP Settings >> Map Groups.
Obtain the group name mapped to the power user role.
Request from the LDAP administrator the group membership of this LDAP group, and compare to the list of individuals appointed by the ISSM.

If using SAML:
Select Settings >> Access Controls >> Authentication Method >> SAML Settings >> Map Groups.
Obtain the group name mapped to the power user role.
Request from the SAML administrator the group membership of this SAML group, and compare to the list of individuals appointed by the ISSM.

If users that are not defined by the ISSM as requiring elevated rights are present in the power user role membership, this is a finding.'
  desc 'fix', 'Provide the list of individuals assigned by the ISSM to be members of the power user role to the LDAP/AD administrator or SAML Identity Provider administrator to add to the security group mapped to the power user role.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23338r569419_chk'
  tag severity: 'low'
  tag gid: 'V-221623'
  tag rid: 'SV-221623r879560_rule'
  tag stig_id: 'SPLK-CL-000270'
  tag gtitle: 'SRG-APP-000090-AU-000070'
  tag fix_id: 'F-23327r569412_fix'
  tag 'documentable'
  tag legacy: ['SV-111337', 'V-102393']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
