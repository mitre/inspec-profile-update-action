control 'SV-251667' do
  title 'Splunk Enterprise must allow only the individuals appointed by the Information System Security Manager (ISSM) to have full admin rights to the system.'
  desc "Without restricting which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'This check is applicable to the instance with the Search Head role, which may be a different instance in a distributed environment.

Select Settings >> Users.

If users have the admin role that are not defined by the ISSM as requiring admin rights, this is a finding.

LDAP Groups Check: 

Select Settings >> Authentication Method >> LDAP Settings >> Map Groups.

Obtain the LDAP group name mapped to the admin role.

Request from the LDAP administrator the group membership of this LDAP group, and compare to the list of individuals appointed by the ISSM.

If users that are not defined by the ISSM as requiring admin rights are present in the admin role membership, this is a finding.'
  desc 'fix', 'Provide the list of individuals assigned by the ISSM to be members of the admin role to the Splunk Enterprise administrator.

Provide the list of individuals assigned by the ISSM to be members of the admin role to the LDAP administrator to add to the LDAP group mapped to the admin role.

Create user accounts and assign the admin role for users provided in the lists.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55105r808235_chk'
  tag severity: 'low'
  tag gid: 'V-251667'
  tag rid: 'SV-251667r808237_rule'
  tag stig_id: 'SPLK-CL-000140'
  tag gtitle: 'SRG-APP-000090-AU-000070'
  tag fix_id: 'F-55059r808236_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
