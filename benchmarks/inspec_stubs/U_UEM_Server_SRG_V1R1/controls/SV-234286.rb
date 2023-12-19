control 'SV-234286' do
  title 'The UEM server must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The application must be configured to automatically provide account management functions and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities. Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server provides automated mechanisms for supporting account management functions.

If the UEM server does not provide automated mechanisms for supporting account management functions, this is a finding.'
  desc 'fix', 'Configure the UEM server to provide automated mechanisms for supporting account management functions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37471r613868_chk'
  tag severity: 'medium'
  tag gid: 'V-234286'
  tag rid: 'SV-234286r617355_rule'
  tag stig_id: 'SRG-APP-000023-UEM-000012'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-37436r613869_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
