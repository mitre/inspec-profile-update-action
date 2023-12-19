control 'SV-239211' do
  title 'VMware Postgres must provide non-privileged users with minimal error information.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, Social Security numbers, and credit card numbers.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.

'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW client_min_messages;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

notice

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET client_min_messages TO 'notice';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42444r679004_chk'
  tag severity: 'medium'
  tag gid: 'V-239211'
  tag rid: 'SV-239211r679006_rule'
  tag stig_id: 'VCPG-67-000019'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-42403r679005_fix'
  tag satisfies: ['SRG-APP-000266-DB-000162', 'SRG-APP-000267-DB-000163']
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
