control 'SV-70831' do
  title 'The operating system must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors.

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated, or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the operating system itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'Verify the operating system provides automated mechanisms for supporting account management functions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide automated mechanisms for supporting account management functions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56571'
  tag rid: 'SV-70831r1_rule'
  tag stig_id: 'SRG-OS-000001-GPOS-00001'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-61459r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
