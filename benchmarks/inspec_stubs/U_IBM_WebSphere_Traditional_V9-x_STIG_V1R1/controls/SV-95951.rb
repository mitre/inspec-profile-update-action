control 'SV-95951' do
  title 'The WebSphere Application Server must generate log records when successful/unsuccessful attempts to access subject privileges occur.'
  desc "Accessing a subject's privileges can be used to elevate a lower-privileged subject's privileges temporarily in order to cause harm to the application server or to gain privileges to operate temporarily for a designed purpose. When these actions take place, the event needs to be logged.

Application servers either provide a local user store, or they integrate with enterprise user stores like LDAP. When the application server provides the user store and enforces authentication, the application server must generate a log record when modification of privileges is successfully or unsuccessfully performed."
  desc 'check', 'In the administrative console, navigate to Security >> Security auditing >> Audit Service Provider.

Click on the providers in the list.

Note: names of all the filters, e.g., "DefaultAuditSpecification_1".

Go back to Security >> Security auditing >> Event type Filters.

Find the filters previously noted.

If you do not see the filter for SECURITY_AUTHN, SECURITY_AUTHZ, SECURITY_AUTHN_TERMINATE, and ADMIN_REPOSITORY_SAVE that has INFO, ERROR, SUCCESS, DENIED, REDIRECT, and WARNING defined, this is a finding.'
  desc 'fix', 'In the administrative console, navigate to Security >> Security auditing >> Audit Service Provider.

Click on the providers in the list.

Note the names of all the filters, e.g., "DefaultAuditSpecification_1".

Go back to Security >> Security auditing >> Event type Filters.

Find the filters previously noted.

If you do not see that the provider filter for SECURITY_AUTHN, SECURITY_AUTHZ, SECURITY_AUTHN_TERMINATE, and ADMIN_REPOSITORY_SAVE that has INFO, ERROR, SUCCESS, DENIED, REDIRECT, and WARNING defined, click the "New" button to create a new filter.

Give it a unique name.

Select "SECURITY_AUTHN" and "ADMIN_REPOSITORY_SAVE" from the "Events to associate with audit filter" field.

Click the right arrow to fill in "Enabled events" field.

From "Event outcomes to associate with an audit filter" field, select INFO, ERROR, SUCCESS, DENIED, REDIRECT, and WARNING.

Click the right arrow to fill in "Enabled event outcomes" field.

Click "OK".

Go back to Security >> Security auditing >> Audit Service Provider >> [provider].

Under "Selectable filters", select the new filter just created.

Click the right arrow to add it to the list.

Click "OK".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80923r1_chk'
  tag severity: 'low'
  tag gid: 'V-81237'
  tag rid: 'SV-95951r1_rule'
  tag stig_id: 'WBSP-AS-000380'
  tag gtitle: 'SRG-APP-000091-AS-000052'
  tag fix_id: 'F-88017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
