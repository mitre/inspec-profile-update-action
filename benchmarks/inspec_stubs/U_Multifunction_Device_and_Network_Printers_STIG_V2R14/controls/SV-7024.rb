control 'SV-7024' do
  title 'The level of audit has not been established or the audit logs being collected for the devices and print spoolers are not being reviewed.'
  desc 'If inadequate information is captured in the audit, the identification and prosecution of malicious user will be very difficult. If the audits are not regularly reviewed suspicious activity may go undetected for a long time.  Therefore, the level of auditing for MFDs, printers, and print spoolers must be defined and personnel identified to review the audit logs.'
  desc 'check', "Obtain and review the organization's MFD and printer security policy.  If the level of auditing has not been established, this is a finding.  If personnel have not been identified to regularly review MFD, printer, and print spooler logs, this is a finding."
  desc 'fix', 'Define the level of auditing and identify personnel responsible for reviewing audit logs of MFDs, printers, and print spoolers.'
  impact 0.3
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3009r2_chk'
  tag severity: 'low'
  tag gid: 'V-6799'
  tag rid: 'SV-7024r2_rule'
  tag stig_id: 'MFD06.006'
  tag gtitle: 'MFD Level of Audit and Reviewing'
  tag fix_id: 'F-6470r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3, ECAT-1, ECAT-2'
end
