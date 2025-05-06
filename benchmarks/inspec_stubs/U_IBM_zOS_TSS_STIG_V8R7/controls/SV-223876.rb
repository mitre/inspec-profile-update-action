control 'SV-223876' do
  title 'CA-TSS MODE Control Option must be set to FAIL.'
  desc "Enterprise environments make account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors.

A comprehensive account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The automated mechanisms may reside within the operating system itself or may be offered by other infrastructure providing automated account management capabilities. Automated mechanisms may be composed of differing technologies that, when placed together, contain an overall automated mechanism supporting an organization's automated account management requirements.

Account management functions include: assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the global MODE Control Option value is set to "FAIL", this is not a finding.

If the global MODE Control Option value is not set to "FAIL", this is a finding. 

Additional analysis may be required under the following conditions:
Mode(IMPL) is allowed while a system is in implementation with a documented process that includes an implementation completion date.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to set the MODE control option to (FAIL) and proceed with the change.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25549r516027_chk'
  tag severity: 'high'
  tag gid: 'V-223876'
  tag rid: 'SV-223876r561402_rule'
  tag stig_id: 'TSS0-ES-000030'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-25537r516028_fix'
  tag 'documentable'
  tag legacy: ['SV-107563', 'V-98459']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
