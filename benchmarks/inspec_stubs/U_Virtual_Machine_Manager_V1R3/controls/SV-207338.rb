control 'SV-207338' do
  title 'The VMM must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the VMM itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the VMM to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'Verify the VMM provides automated mechanisms for supporting account management functions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide automated mechanisms for supporting account management functions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7595r365424_chk'
  tag severity: 'medium'
  tag gid: 'V-207338'
  tag rid: 'SV-207338r378478_rule'
  tag stig_id: 'SRG-OS-000001-VMM-000010'
  tag gtitle: 'SRG-OS-000001'
  tag fix_id: 'F-7595r365425_fix'
  tag 'documentable'
  tag legacy: ['V-56553', 'SV-70813']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
