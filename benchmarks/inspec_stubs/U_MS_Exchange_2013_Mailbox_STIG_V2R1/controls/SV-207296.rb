control 'SV-207296' do
  title 'Exchange email-forwarding SMTP domains must be restricted.'
  desc 'Auto-forwarded email accounts do not meet the requirement for digital signature and encryption of CUI and PII IAW DoDI 8520.2 (reference ee) and DoD Director for Administration and Management memorandum, "Safeguarding Against and Responding to the Breach of Personally Identifiable Information".

Use of forwarding set by an administrator interferes with nonrepudiation requirements that each end user be responsible for creation and destination of email data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine any accounts that have been authorized to have email auto-forwarded.

Note: If email auto-forwarding is not being used, this check is not applicable.

Open the Exchange Management Shell and enter the following commands:

Get-RemoteDomain | Select Name, Identity, DomainName, AutoForwardEnabled

If any domain for a user forwarding SMTP address is not documented in the EDSP, this is a finding.

Note: If no remote SMTP domain matching the mail-enabled user or contact that allows forwarding is configured for users identified with a forwarding address, this function will not work properly.'
  desc 'fix', 'Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set- RemoteDomain -Identity <RemoteDomainIdParameter>'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7554r393401_chk'
  tag severity: 'medium'
  tag gid: 'V-207296'
  tag rid: 'SV-207296r615936_rule'
  tag stig_id: 'EX13-MB-000150'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-7554r393402_fix'
  tag 'documentable'
  tag legacy: ['SV-84621', 'V-69999']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
