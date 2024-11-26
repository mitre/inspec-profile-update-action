control 'SV-224166' do
  title 'If DBMS authentication, using passwords, is employed, EDB Postgres Advanced Server must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', %q(If DBMS authentication, using passwords, is not employed, this is not a finding.

In a SQL window, run this command:

select * from dba_profiles;

If there are UNLIMITED or NULL values in the "limit" column, this is a finding.

Review the password verification functions specified for the PASSWORD_VERIFY_FUNCTION settings for each profile. Determine whether the following rules are enforced by the code in those functions. If any are not, this is a finding.
a. minimum of 15 characters, including at least one of each of the following character sets:
- Upper-case
- Lower-case
- Numerics
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight

Review the DBMS settings relating to password lifetime. Determine whether the following rules are enforced. If any are not, this is a finding.
a. Password lifetime limits for interactive accounts: Minimum 24 hours, maximum 60 days
b. Password lifetime limits for non-interactive accounts: Minimum 24 hours, maximum 365 days
c. Number of password changes before an old one may be reused: Minimum of five)
  desc 'fix', %q(After creating a password verification function, configure the default profile to use it and to the other required password related settings.

To facilitate checking that a new password is sufficiently different from a previously used one, the dod_verify_password function uses the Levenshtein function, which is available as part of the PostgreSQL fuzzystrmatch extension. 

Before creating the password verification function, check whether the fuzzystrmatch extension is installed by executing the following SQL query as enterprisedb:

 SELECT extname FROM pg_extension;

If "fuzzystrmatch" is not listed, execute the following SQL to install the extension as enterprisedb:

 CREATE EXTENSION fuzzystrmatch;

With the fuzzystrmatch extension installed, execute the following SQL statements as enterprisedb:

 CREATE OR REPLACE FUNCTION sys.dod_verify_password(user_name varchar2, new_password varchar2, old_password varchar2) 
 RETURN boolean IMMUTABLE 
 IS 
 pwd_length integer := NVL( length(new_password), 0 );

 min_length integer := 15;
 min_lower integer := 1;
 min_upper integer := 1;
 min_numeric integer := 1;
 min_special integer := 1;
 min_diff integer := ceil(min_length::numeric / 2);

 cnt_lower integer := 0;
 cnt_upper integer := 0;
 cnt_numeric integer := 0;
 cnt_special integer := 0;

 cnt_diff integer := 0;

 i integer ;
 curr_char CHAR(1);

 BEGIN 

 --
 -- Check Length of new password
 --
 IF ( pwd_length < min_length ) 
 THEN 
 raise_application_error(-20001, 'Password is too short. Password must be at least '||min_length||' characters long.'); 
 END IF;

 --
 -- Get count of each character type in new password.
 --
 FOR i in 1..pwd_length LOOP
 curr_char := substr(new_password, i, 1);

 IF ( curr_char SIMILAR TO '[a-z]' ) THEN
 cnt_lower := cnt_lower + 1;
 ELSIF ( curr_char SIMILAR TO '[A-Z]' ) THEN
 cnt_upper := cnt_upper + 1;
 ELSIF ( curr_char SIMILAR TO '[0-9]' ) THEN
 cnt_numeric := cnt_numeric + 1;
 ELSE
 cnt_special := cnt_special + 1;
 END IF;
 END LOOP;

 --
 -- Calculate Levenshtein difference between old and new password
 --
 cnt_diff := levenshtein( old_password, new_password );

 -- Check if new password has minimum number of lowercase characters
 IF cnt_lower < min_lower THEN
 raise_application_error(-20004, 'Password must contain at least '||min_lower||' lowercase character(s)'); 
 END IF;

 -- Check if new password has minimum number of uppercase characters
 IF cnt_upper < min_upper THEN
 raise_application_error(-20003, 'Password must contain at least '||min_upper||' uppercase character(s)'); 
 END IF;

 -- Check if new password has minimum number of numeric characters
 IF cnt_numeric < min_numeric THEN
 raise_application_error(-20005, 'Password must contain at least '||min_numeric||' numeric character(s)'); 
 END IF;

 -- Check if new password has minimum number of special characters
 IF cnt_special < min_special THEN
 raise_application_error(-20006, 'Password must contain at least '||min_special||' special character(s)'); 
 END IF;

 -- Check if new password differs from old password by minimum number of required characters
 IF cnt_diff < min_diff THEN
 raise_application_error(-20007, 'Password must differ from old password by at least '||min_diff||' character(s)'); 
 END IF;


 RETURN true; 
 END; 

 ALTER FUNCTION sys.dod_verify_password(varchar2, varchar2, varchar2) OWNER TO enterprisedb;

Next, execute the following statement (or a variant of this) to set the default profile for DoD standards:

 ALTER PROFILE DEFAULT LIMIT
 FAILED_LOGIN_ATTEMPTS 3 
 PASSWORD_LOCK_TIME 1
 PASSWORD_LIFE_TIME 60
 PASSWORD_GRACE_TIME 3
 PASSWORD_REUSE_TIME 180
 PASSWORD_REUSE_MAX 5
 PASSWORD_VERIFY_FUNCTION dod_verify_password;

Note that the above statement assumes that the password verification function is named "dod_verify_password". If the function was created with a different name, update the ALTER PROFILE statement above as appropriate.)
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25839r495516_chk'
  tag severity: 'high'
  tag gid: 'V-224166'
  tag rid: 'SV-224166r836874_rule'
  tag stig_id: 'EP11-00-004250'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-25827r495517_fix'
  tag 'documentable'
  tag legacy: ['SV-109463', 'V-100359']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
