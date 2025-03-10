control 'SV-228397' do
  title 'Exchange servers must have an approved DoD email-aware virus protection software installed.'
  desc 'With the proliferation of trojans, viruses, and spam attaching themselves to email messages (or attachments), it is necessary to have capable email-aware anti-virus (AV) products to scan messages and identify any resident malware. Because email messages and their attachments are formatted to the MIME standard, a flat-file AV scanning engine is not suitable for scanning email message stores. 

Email-aware anti-virus engines must be Exchange 2016 compliant. Competent email scanners will have the ability to scan mail stores, attachments (including zip or other archive files) and mail queues and to issue warnings or alerts if malware is detected. As with other AV products, a necessary feature to include is the ability for automatic updates.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the anti-virus strategy. 

Verify the email-aware anti-virus scanner product is Exchange 2016 compatible and DoD approved. 

If email servers are using an email-aware anti-virus scanner product that is not DoD approved and Exchange 2016 compatible, this is a finding.'
  desc 'fix', "Update the EDSP to specify the organization's anti-virus strategy.

Install and configure a DoD-approved compatible Exchange 2016 email-aware anti-virus scanner product."
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30630r496987_chk'
  tag severity: 'high'
  tag gid: 'V-228397'
  tag rid: 'SV-228397r879653_rule'
  tag stig_id: 'EX16-MB-000530'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30615r496988_fix'
  tag 'documentable'
  tag legacy: ['SV-95419', 'V-80709']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
