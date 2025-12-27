control 'SV-254088' do
  title 'Innoslate must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The application must be configured to automatically provide account management functions and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities. Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements. 

Account management functions include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', '1. Enter the settings.properties file located at C:\\Innoslate4\\apache-tomcat\\webapps\\Innoslate4\\WEB-INF.
2. Find the "default organization" field.
3. Enter the default organization name to automatically add users to once they sign in.
4. Find the "Email notifications" fields.
5. Verify the email information is correct. If not, this is a finding.'
  desc 'fix', '1. Enter the settings.properties file located at C:\\Innoslate4\\apache-tomcat\\webapps\\Innoslate4\\WEB-INF.
2. Find the "default organization" field.
3. Enter the default organization name to automatically add users to once they sign in.
4. Find the "Email notifications" fields.
5. Add the email information in the required fields.
6. Save.
7. Restart Service.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57573r845238_chk'
  tag severity: 'medium'
  tag gid: 'V-254088'
  tag rid: 'SV-254088r845240_rule'
  tag stig_id: 'SPEC-IN-000045'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-57524r845239_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
