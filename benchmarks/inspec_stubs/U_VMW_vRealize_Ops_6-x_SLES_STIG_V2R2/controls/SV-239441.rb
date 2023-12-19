control 'SV-239441' do
  title 'The SLES for vRealize must provide automated mechanisms for supporting account management functions.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors.

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the SLES for vRealize itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'Interview the server admin to determine if there is automated mechanisms for managing user accounts. If there is not, this is a finding.'
  desc 'fix', 'Implement an automated system for managing user accounts that minimizes the risk of errors, either intentional or deliberate. If possible, this system should integrate with an existing enterprise user management system, such as, one based Active Directory or Kerberos.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42674r661772_chk'
  tag severity: 'medium'
  tag gid: 'V-239441'
  tag rid: 'SV-239441r661774_rule'
  tag stig_id: 'VROM-SL-000005'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-42633r661773_fix'
  tag 'documentable'
  tag legacy: ['SV-99003', 'V-88353']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
