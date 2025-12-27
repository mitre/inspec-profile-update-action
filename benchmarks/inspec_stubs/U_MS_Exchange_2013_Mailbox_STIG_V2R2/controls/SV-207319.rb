control 'SV-207319' do
  title 'Exchange servers must have an approved DoD email-aware virus protection software installed.'
  desc 'With the proliferation of trojans, viruses, and spam attaching themselves to email messages (or attachments), it is necessary to have capable email-aware antivirus (AV) products to scan messages and identify any resident malware. Because email messages and their attachments are formatted to the MIME standard, a flat-file AV scanning engine is not suitable for scanning email message stores. 

Email-aware antivirus engines must be Exchange 2013 compliant. Competent email scanners will have the ability to scan mail stores, attachments (including zip or other archive files) and mail queues and to issue warnings or alerts if malware is detected. As with other AV products, a necessary feature to include is the ability for automatic updates.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the antivirus strategy. 

Verify the email-aware antivirus scanner product is Exchange 2013 compatible and DoD-approved. 

If email servers are using an email-aware antivirus scanner product that is not DoD-approved and Exchange 2013 compatible, this is a finding.'
  desc 'fix', 'Update the EDSP.

Install and configure a DoD-approved compatible Exchange 2013 email-aware antivirus scanner product.'
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7577r393470_chk'
  tag severity: 'high'
  tag gid: 'V-207319'
  tag rid: 'SV-207319r615936_rule'
  tag stig_id: 'EX13-MB-000265'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-7577r393471_fix'
  tag 'documentable'
  tag legacy: ['SV-84667', 'V-70045']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
