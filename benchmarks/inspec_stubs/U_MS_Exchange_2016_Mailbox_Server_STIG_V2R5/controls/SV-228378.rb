control 'SV-228378' do
  title 'Exchange email-forwarding SMTP domains must be restricted.'
  desc 'Auto-forwarded email accounts do not meet the requirement for digital signature and encryption of Controlled Unclassified Information (CUI) and Personally Identifiable Information (PII) in accordance with DoDI 8520.2 (reference ee) and DoD Director for Administration and Management memorandum, "Safeguarding Against and Responding to the Breach of Personally Identifiable Information".

Use of forwarding set by an administrator interferes with nonrepudiation requirements that each end user be responsible for creation and destination of email data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information. 

Determine any accounts that have been authorized to have email auto-forwarded.

Note: If email auto-forwarding is not being used, this check is not applicable (NA).

Open the Exchange Management Shell and enter the following commands:

Get-RemoteDomain | Select Name, Identity, DomainName, AutoForwardEnabled

If any domain for a user forwarding SMTP address is not documented in the EDSP, this is a finding.

Note: If no remote SMTP domain matching the mail-enabled user or contact that allows forwarding is configured for users identified with a forwarding address, this function will not work properly.'
  desc 'fix', 'Update the EDSP to specify any accounts that have been authorized to have email auto-forwarded or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set- RemoteDomain -Identity <RemoteDomainIdParameter>'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30611r496930_chk'
  tag severity: 'medium'
  tag gid: 'V-228378'
  tag rid: 'SV-228378r879642_rule'
  tag stig_id: 'EX16-MB-000300'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-30596r496931_fix'
  tag 'documentable'
  tag legacy: ['SV-95381', 'V-80671']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
