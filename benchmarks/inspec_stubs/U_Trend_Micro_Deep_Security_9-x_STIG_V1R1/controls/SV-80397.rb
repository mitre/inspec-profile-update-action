control 'SV-80397' do
  title 'Trend Deep Security must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The application must be configured to automatically provide account management functions and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities. Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements. 

Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'Review the Trend Deep Security server configuration to ensure automated mechanisms for supporting account management functions are automated.

Interview the ISSO to determine a list of authorized users and their perspective roles supporting the application.  Review the identified users within the following:

Administration >> User Management >> Users >> Assign Role

If the identified users do not match the roles assigned within the application this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to provide automated mechanisms for supporting account management functions.

Configure the user permissions according to their assigned roles within the organization. 

Administration >> User Management >> Users >> Assign Role'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66555r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65907'
  tag rid: 'SV-80397r1_rule'
  tag stig_id: 'TMDS-00-000015'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-71983r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
