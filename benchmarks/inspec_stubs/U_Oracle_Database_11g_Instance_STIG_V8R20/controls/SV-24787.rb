control 'SV-24787' do
  title 'Password reuse should be prevented where supported by the DBMS.'
  desc 'Password reuse restrictions protect against bypass of password expiration requirements and help protect accounts from password guessing attempts. The DoDI 8500.2 specifies preventing password reuse to the extent system capabilities permit.

The PASSWORD_REUSE_MAX value specifies the number of password changes before a password can be reused. The PASSWORD_REUSE_TIME value specifies the length of time before a password can be reused.'
  desc 'check', "If no DBMS accounts authenticate using passwords, this check is Not a Finding.

Review DBMS account password reuse restrictions:

From SQL*Plus:
  select p1.profile profile, p1.limit REUSE_MAX, p2.limit REUSE_TIME
  from dba_profiles p1, dba_profiles p2
  where p1.profile = p2.profile
  and p1.resource_name = 'PASSWORD_REUSE_MAX'
  and p2.resource_name = 'PASSWORD_REUSE_TIME'
  order by p1.profile;

If limits for REUSE_MAX and REUSE_TIME are set to UNLIMITED, this is a Finding.

If limits for REUSE_MAX and REUSE_TIME are not set to values, this is a Finding.

NOTE: If limits for REUSE_MAX or REUSE_TIME are set to DEFAULT refer to the corresponding limits set for the DEFAULT profile.

If the DBMS uses Host Authentication, confirm that the host is configured to prevent password reuse.  If it is not, this is a Finding."
  desc 'fix', 'Configure the DBMS to prevent password reuse by modifying Oracle profiles:

From SQL*Plus:

 alter profile default limit
 password_reuse_max 10
 password_reuse_time UNLIMITED;
  
 alter profile [profile name] limit
 password_reuse_max default
 password_reuse_time default;
 
Replace [profile name] with any existing, non-default profile names.

Where Host Authentication is used, configure the OS to prevent password reuse.

Consider configuring the DBMS to use alternate authentication methods other than password authentication where supported by the DBMS.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29358r4_chk'
  tag severity: 'medium'
  tag gid: 'V-15633'
  tag rid: 'SV-24787r2_rule'
  tag stig_id: 'DG0126-ORACLE11'
  tag gtitle: 'DBMS account password reuse'
  tag fix_id: 'F-26384r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
