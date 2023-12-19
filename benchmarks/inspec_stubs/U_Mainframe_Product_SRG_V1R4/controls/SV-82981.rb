control 'SV-82981' do
  title 'The Mainframe Product must configure malicious code protection mechanisms to perform periodic scans of the information system every seven days.'
  desc 'Malicious code protection mechanisms include, but are not limited to, anti-virus and malware detection software. Malicious code protection mechanisms specific to Mainframe Products are designed to periodically scan system files to validate their integrity. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, Trojan horses, and spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'If the Mainframe Product has no function or capability for providing malicious code scanning or protection, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to perform periodic scans of information system every seven days, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to perform periodic scans of information system every seven days.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69023r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68491'
  tag rid: 'SV-82981r1_rule'
  tag stig_id: 'SRG-APP-000277-MFP-000354'
  tag gtitle: 'SRG-APP-000277-MFP-000354'
  tag fix_id: 'F-74607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
