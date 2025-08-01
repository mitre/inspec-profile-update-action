control 'SV-79561' do
  title 'The DataPower Gateway must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Privileged account user log on to default domain >> Administration >> Access >> User Group >> Click the "groupISSM" group >> Confirm that the following minimal access profiles are created: "*/*/*?Access=r" and "*/default/logging/target?Name=logTargetISSM&Access=r+w+a+d+x". If either profile is not present, this is a finding.

Privileged account user log on to default domain >> Administration >> Access >> RBM Settings >> Click "Credential Mapping" >> If Credential-mapping method is not "Local user group" or "Search LDAP for group name" is off, this is a finding.'
  desc 'fix', 'Create an ISSM User Group: Privileged account user log on to default domain >> Administration >> Access >> User Group >> Click the "Add" button >> Name: "groupISSM" >> Enter "*/*/*?Access=r" into the "Access Profile" field >> Click "Add" >> "*/default/logging/target?Name=logTargetISSM&Access=r+w+a+d+x" into the "Access Profile" field >> Click "Add" >> Click "Apply".

Add users’ accounts to the ISSM User Group "groupISSM" in the remote Authentication/Authorization server (LDAP). Note: This takes place outside the context of the IBM DataPower Gateway. Specific instructions will depend on the LDAP server being used.

Configure Role-Based Management to use LDAP Group information during logon to map users to local group definitions.

Administration >> Access >> RBM Settings >> When configuring the Authentication method, select "LDAP" as the authentication method 

Configure LDAP Authentication

Define the connection to the LDAP server >> In the Server host field, enter the IP address or host name of the server >> In the Server port field, enter the port number of the server >> From the LDAP version list, select the version >> From the SSL proxy profile list, select a profile to establish a secured connection to the LDAP server >> From the Load balancer group list, select a load balancer group.

If selected, queries are balanced in accordance with the group settings. This setting overrides the settings for the server host and port.

Set the Search LDAP for DN property to use an LDAP search to retrieve the user group >> In the LDAP read timeout field, enter the time to wait for a response from the server before the appliance closes the connection >> From the Local accounts for fallback list, select whether to use local user accounts as fallback users. 

With fallback users, local users can log on to the appliance if authentication fails or during a network outage that affects the primary authentication.

When specific users are fallback users, add the local users (from the Fallback user list, select a local user) >> Click Add >> Optional: Repeat this step to add another locally defined fallback user.

Define the credentials-mapping method.

Click Credentials-mapping >> From the Credentials-mapping method list, select the method to evaluate access profiles. Although available, a local user group is not a valid selection (If custom: In the Custom URL field, specify the URL of the custom style sheet; if with an XML file: In the XML file URL field, specify the URL of the RBM file) >> When the mapping method is a local user group or an XML file, set Search LDAP for group name to control whether to search LDAP to retrieve all user groups that match the query.

When LDAP search is enabled, define the LDAP connection >> In the Server host field, enter the IP address or host name of the server >> In the Server port field, enter the port number of the server >> From the SSL proxy profile list, select the profile to establish a secured connection to the server >> From the Load balancer group list, select a load balancer group. If selected, queries are balanced in accordance with the group settings. This setting overrides the settings for the server host and port

In the LDAP bind DN field, enter the distinguished name (DN) for the bind operation >> In the LDAP bind password fields, enter and confirm the password for the specified DN >> From the LDAP search parameters list, select an LDAP search parameter. The LDAP search operation uses these parameters to retrieve all group names (DN or attribute value) based on the DN of the authenticated user >> In the LDAP read timeout field, enter the time to wait for a response from the server before the appliance closes the connection >> Define the account policy >> If you defined fallback users, define the password policy. 

Save the configuration: Click "Apply" to save the changes to the running configuration >> Click "Save Configuration" to save the changes to the persisted configuration.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65697r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65071'
  tag rid: 'SV-79561r1_rule'
  tag stig_id: 'WSDP-NM-000023'
  tag gtitle: 'SRG-APP-000090-NDM-000222'
  tag fix_id: 'F-71011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
