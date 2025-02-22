control 'SV-50976' do
  title 'Email forwarding SMTP domains must be restricted.'
  desc "Auto-forwarded email accounts do not meet the requirement for digital signature and encryption of CUI and PII IAW DoDI 8520.2 (reference ee) and DoD Director for Administration and Management memorandum, 'Safeguarding Against and Responding to the Breach of Personally Identifiable Information.’

Use of forwarding set by an administrator interferes with non-repudiation requirements that each end user be responsible for creation and destination of email data."
  desc 'check', 'Obtain the Email Domain Security Plan (EDSP) and locate any accounts that have been authorized to have email auto-forwarded.

Open the Exchange Management Shell and enter the following commands:

Get-RemoteDomain | select name, AutoForwardEnabled

If any domain for user forwarding SMTP address is not documented in the EDSP, this is a finding.

Note: If no remote SMTP domain matching the mail-enabled user or contact that allows forwarding is configured for users identified with a forwarding address, this function will not work properly. This requirement works with Exch-1-321.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set- RemoteDomain -Identity <RemoteDomainIdParameter>'
  impact 0.5
  ref 'DPMS Target Mailbox Server'
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-46506r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39160'
  tag rid: 'SV-50976r1_rule'
  tag stig_id: 'Exch-1-324'
  tag gtitle: 'Exch-1-324'
  tag fix_id: 'F-44138r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
