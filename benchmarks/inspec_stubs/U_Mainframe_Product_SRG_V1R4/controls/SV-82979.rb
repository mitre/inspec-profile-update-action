control 'SV-82979' do
  title 'The Mainframe Product must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc "Malicious code includes viruses, worms, Trojan horses, and spyware. Malicious code specific to mainframes may be any code that corrupts system files. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.

This requirement applies to applications providing malicious code protection. Malicious code protection mechanisms include, but are not limited to, anti-virus and malware detection software. Malicious code protection mechanisms specific to Mainframe Products are designed to periodically scan system files to validate their integrity. Malicious code protection mechanisms (including signature definitions and rule sets) must be updated when new releases are available."
  desc 'check', 'If the Mainframe Product has no function or capability for providing malicious code scanning or protection, this is not applicable.

Refer to organizational configuration management policy and procedures.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to install new releases using organizational configuration management policy and procedure, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to install new releases using organizational configuration management policy and procedures.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69021r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68489'
  tag rid: 'SV-82979r1_rule'
  tag stig_id: 'SRG-APP-000276-MFP-000353'
  tag gtitle: 'SRG-APP-000276-MFP-000353'
  tag fix_id: 'F-74605r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
