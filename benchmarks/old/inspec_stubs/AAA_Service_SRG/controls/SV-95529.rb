control 'SV-95529' do
  title 'AAA Services must be configured to provide automated account management functions.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to disable inactive accounts after a specified time period, or to lock accounts after a specified number of unsuccessful attempts at logon.

AAA Services must be configured to automatically provide account management functions, and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within AAA Services or may be directory services providing automated account management externally. Automated mechanisms may be composed of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements. 

Account management functions include assignment of role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example, using email or text messaging to automatically notifying account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Verify AAA Services are configured to provide automated account management functions. Automated functions include disabling accounts after specified periods of inactivity, locking accounts after a specified number of incorrect logon attempts, etc. Where possible, automated functions must be performed on users and devices globally rather than by each individual account.

If AAA Services do not provide automated account management functions, this is a finding.'
  desc 'fix', 'Configure AAA Services to provide automated account management functions. Automated functions include disabling accounts after specified periods of inactivity, locking accounts after a specified number of incorrect logon attempts, etc. Where possible, automated functions must be performed on users and devices globally rather than by each individual account.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80555r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80819'
  tag rid: 'SV-95529r1_rule'
  tag stig_id: 'SRG-APP-000023-AAA-000030'
  tag gtitle: 'SRG-APP-000023-AAA-000030'
  tag fix_id: 'F-87673r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
