control 'SV-223422' do
  title 'CA-ACF2 OPTS GSO record must be set to ABORT mode.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors.

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the operating system itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage.

"
  desc 'check', 'From the ISPF Command Shell enter "ACF" to enter ACF2 Command shell.

Enter "SHOW STATE".

If the "GSO OPTS" record show a "MODE= ABORT", this is not a finding.'
  desc 'fix', 'Configure the GSO Option for "MODE" to equal "ABORT".'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25095r500396_chk'
  tag severity: 'high'
  tag gid: 'V-223422'
  tag rid: 'SV-223422r533198_rule'
  tag stig_id: 'ACF2-ES-000010'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-25083r500397_fix'
  tag satisfies: ['SRG-OS-000001-GPOS-00001', 'SRG-OS-000480-GPOS-00229']
  tag 'documentable'
  tag legacy: ['SV-106645', 'V-97541']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
