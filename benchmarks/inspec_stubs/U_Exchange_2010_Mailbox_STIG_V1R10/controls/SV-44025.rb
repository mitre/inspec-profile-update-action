control 'SV-44025' do
  title 'Email forwarding must be restricted.'
  desc "Auto-forwarded email accounts do not meet the requirement for digital signature and encryption of CUI and PII IAW DoDI 8520.2 (reference ee) and DoD Director for Administration and Management memorandum, 'Safeguarding Against and Responding to the Breach of Personally Identifiable Information.’

Use of forwarding set by an administrator interferes with non-repudiation requirements that each end user be responsible for creation and destination of email data."
  desc 'check', 'Access Active Directory for mailbox enabled user accounts with the msExchGenericForwardingAddress attribute set. Obtain the Email Domain Security Plan (EDSP) and locate any accounts that have been authorized to have email auto-forwarded.

Open the Exchange Management Shell and enter the following commands:

Get-Mailbox -Filter {ForwardingSMTPAddress -ne $null}

If any user has a forwarding SMTP address and is not documented in the EDSP, this is a finding.

Note: If no remote SMTP domain matching the mail-enabled user or contact that allows forwarding is configured for users identified with a forwarding address, this function will not work properly. This requirement works with Exch-1-324.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-Mailbox -Identity <'UserWithForwardedAddress'> -ForwardingSMTPAdddress $null"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41712r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33605'
  tag rid: 'SV-44025r2_rule'
  tag stig_id: 'Exch-1-321'
  tag gtitle: 'Exch-1-321'
  tag fix_id: 'F-37497r1_fix'
  tag 'documentable'
end
