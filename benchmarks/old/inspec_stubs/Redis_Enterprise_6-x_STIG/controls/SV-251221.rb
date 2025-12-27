control 'SV-251221' do
  title 'Redis Enterprise DBMS must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'The DoD standard for authentication of an interactive user is the presentation of a Common Access Card (CAC) or other physical token bearing a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate, coupled with a Personal Identification Number (PIN) to be entered by the user at the beginning of each session and whenever reauthentication is required.

Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.

For more information refer to:
https://docs.redislabs.com/latest/rs/administering/access-control/'
  desc 'check', 'Review the system documentation and the configuration of Redis Enterprise and related applications and tools.

If the information owner has identified additional cases where reauthentication is needed, but there are circumstances where the system does not ask the user to reauthenticate when those cases occur, this is a finding.

Redis Enterprise requires users to reauthenticate after the configured time-out period has been met, but does not require reauthentication when permissions are updated; permissions are automatically updated and applied on both the database and the Redis Enterprise web UI. Only admin users can modify privileges and roles.'
  desc 'fix', %q(Confirm with information owner any circumstances under which a user is required to reauthenticate. If any exist, confirm they are properly documented.

Configure Redis Enterprise settings to meet organizationally defined requirements:
User account security 

To ensure user accounts are secured and not misused, RS supports enforcement of:
- Password complexity
- Password expiration
- Account lock on failed attempts
- Account inactivity timeout

To enforce a more advanced password policy that meets the desired contractual and compliance requirements and associated organizational policies, it is recommend to use LDAP integration with an external identity provider, such as Active Directory.

Resetting user passwords: 
To reset a user password from the CLI, run:
rladmin cluster reset_password <username>

The user is asked to enter and confirm the new password.

Setting up local password complexity:
RS allows for enforcement of a password complexity profile that meets most organizational needs. The password complexity profile is defined by:
- At least 8 characters
- At least one uppercase character
- At least one lowercase character
- At least one number (not first or last character)
- At least one special character (not first or last character)
- Does not contain the User ID or reverse of the User ID
- No more than three repeating characters
Note: The password complexity profile applies to when a new user is added or an existing user changes their password.

To enforce the password complexity profile, run:
curl -k -X PUT -v -H "cache-control: no-cache" -H "content-type: application/json" -u "<administrator-user-email>:<password>" -d '{"password_complexity":true}' https://<RS_server_address>:9443/v1/cluster

Setting local user password expiration: 
RS allows for enforced password expiration to meet compliance and contractual requirements. To enforce an expiration of a local user password after a specified number of days, run:
curl -k -X PUT -v -H "cache-control: no-cache" -H "content-type: application/json" -u "<administrator_user>:<password>" -d '{"password_expiration_duration":<number_of_days>}' https://<RS_server_address>:9443/v1/cluster
To disable password expiration, set the number of days to 0.

Account lock on failed attempts: 
To prevent unauthorized access to RS, organizations may enforce account lockout after a specified number of failed login attempts.

Session timeout: 
When logging in to the web UI, the account is automatically logged out after 15 minutes of inactivity.

To change the duration of inactivity that causes the timeout:
From rladmin, run: rladmin cluster config cm_session_timeout_minutes <minutes>

From the REST API, run:
curl --request PUT \
  --url https://localhost:9443/v1/cluster \
  --header 'content-type: application/json' \
  --data '{
"cm_session_timeout_minutes": <minutes>
}')
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54656r804851_chk'
  tag severity: 'medium'
  tag gid: 'V-251221'
  tag rid: 'SV-251221r855613_rule'
  tag stig_id: 'RD6X-00-008500'
  tag gtitle: 'SRG-APP-000389-DB-000372'
  tag fix_id: 'F-54610r804852_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
