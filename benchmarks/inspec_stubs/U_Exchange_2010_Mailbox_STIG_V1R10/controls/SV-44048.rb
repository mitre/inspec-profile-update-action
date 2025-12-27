control 'SV-44048' do
  title 'Email servers must have Email aware virus protection.'
  desc 'With the proliferation of trojans, viruses, and SPAM attaching themselves to email messages (or attachments), it is necessary to have capable email Aware Anti-Virus (AV) products to scan messages and identify any resident malware. Because email messages and their attachments are formatted to the MIME standard, a flat-file AV scanning engine is not suitable for scanning email message stores. 

Email aware Anti-Virus engines must be Exchange 2010 compliant, or use VirusScan Application Program Interface (VSAPI) version 2.6 or higher, which is able to scan email MIME content safely. Competent email scanners will have the ability to scan mail stores, attachments (including zip or other archive files) and mail queues, and to issue warnings or alerts if malware is detected. As with other AV products, a necessary feature to include is the ability for automatic updates.'
  desc 'check', 'Obtain the email Domain Security Plan (EDSP) and locate the anti-virus strategy information. 
Validate that the message stores AV scanner product is Exchange 2010 compatible or VSAPI 2.6 compliant.  

If email servers are using email-aware AV product that is Exchange 2010 compliant or has VSAPI version 2.6 or higher, this is not a finding.'
  desc 'fix', 'Install or upgrade scanning products to VSAPI version 2.6 or higher.

Configure mail stores to be scanned with products at VSAPI version 2.6 or higher.'
  impact 0.7
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41734r1_chk'
  tag severity: 'high'
  tag gid: 'V-33628'
  tag rid: 'SV-44048r1_rule'
  tag stig_id: 'Exch-3-811'
  tag gtitle: 'Exch-3-811'
  tag fix_id: 'F-37520r3_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
