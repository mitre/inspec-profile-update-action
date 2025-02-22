control 'SV-237735' do
  title 'The DBMS must enforce password maximum lifetime restrictions.'
  desc "Password maximum lifetime is the maximum period of time, (typically in days) a user's password may be in effect before the user is forced to change it.

Passwords need to be changed at specific policy-based intervals as per policy. Any password, no matter how complex, can eventually be cracked.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

The PASSWORD_LIFE_TIME parameter defines the number of days a password remains valid. This can must not be set to UNLIMITED. Further, the PASSWORD_GRACE_TIME parameter, if set to UNLIMITED, can nullify the PASSWORD_LIFE_TIME. PASSWORD_GRACE_TIME must be set to 0 days (or another small integer).

Note: User authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. With respect to Oracle, this requirement applies to cases where it is necessary to have accounts directly managed by Oracle."
  desc 'check', %q(If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

Review DBMS settings to determine if passwords must be changed periodically. Run the following script:

    SELECT profile,
     max(decode(resource_name, 'PASSWORD_LIFE_TIME', decode(limit, 'UNLIMITED', 9999, limit)))  +
     max(decode(resource_name, 'PASSWORD_GRACE_TIME', decode(limit, 'UNLIMITED', 9999, limit))) "EFFECTIVE_TIME"
  FROM dba_profiles
  WHERE resource_name = 'PASSWORD_LIFE_TIME'
  OR resource_name = 'PASSWORD_GRACE_TIME'
  GROUP BY profile
  ORDER BY profile;

If the EFFECTIVE_TIME is greater than 60 for any profile applied to user accounts, and the need for this has not been documented and approved by the ISSO, this is a finding.

If PASSWORD_LIFE_TIME or PASSWORD_GRACE_TIME is set to "UNLIMITED", this is a finding.)
  desc 'fix', 'For user accounts managed by Oracle, modify DBMS settings to force users to periodically change their passwords. For example, using "PPPPPP" to stand for a profile name:
ALTER PROFILE PPPPPP LIMIT PASSWORD_LIFE_TIME 35 PASSWORD_GRACE_TIME 0;
Do this for each profile applied to user accounts.

(Note: Although the DoD requirement is for a password change every 60 days, using a value of 35 facilitates the use of PASSWORD_LIFE_TIME as a means of locking accounts inactive for 35 days. But if 35 is not a practical or acceptable limit for password lifetime, set it to the standard DoD value of 60.)

Where a password lifetime longer than 60 is needed, document the reasons and obtain ISSO approval.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40954r836903_chk'
  tag severity: 'medium'
  tag gid: 'V-237735'
  tag rid: 'SV-237735r836904_rule'
  tag stig_id: 'O121-C2-015200'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-40917r822490_fix'
  tag 'documentable'
  tag legacy: ['V-61739', 'SV-76229']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
