control 'SV-251224' do
  title 'Redis Enterprise DBMS must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.

For more information on configuring time out periods on Redis Enterprise refer to:
https://docs.redislabs.com/latest/rs/administering/access-control/'
  desc 'check', 'Interview the system administrator to determine what, if any, the organizational policy is for cached authentication. By default, Redis Enterprise terminates authenticators after a user logs or times out.

To view the current time out period for authentication, log in to the RHEL server that the Redis Enterprise database is hosted on as an admin user.
1. Type: rladmin
2. Once rladmin is started, type: info cluster  

Check documentation to verify that organizationally defined limits, if any, have been set. Compare documentation to actual settings found on the DB. 

If the settings do not match the documentation, this is a finding.'
  desc 'fix', 'Configure Redis Enterprise settings to meet organizationally defined requirements. To configure the time out period, refer to Redis Enterprise Documentation: 

To set time out period for authentication, log in to the RHEL server that the Redis Enterprise database is hosted on as an admin user. Escalate to root privileges.
1. Type: rladmin
2. Once rladmin is started, type:  cluster config cm_session_timeout_minutes <value_to_enter>

By default, the timeout is set to 15 minutes.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54659r804860_chk'
  tag severity: 'medium'
  tag gid: 'V-251224'
  tag rid: 'SV-251224r855614_rule'
  tag stig_id: 'RD6X-00-009000'
  tag gtitle: 'SRG-APP-000400-DB-000367'
  tag fix_id: 'F-54613r804861_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
