control 'SV-82663' do
  title 'The Mainframe Product must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse, and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Examine installation and configuration settings.

Verify the Mainframe Product provides logging for execution of privileged functions through use of SMF, the SYSLOG, the external security management software log, or to some other reliable log file. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to log the execution of privileged functions using the external security manager, SMF, and/or the SYSLOG.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68173'
  tag rid: 'SV-82663r1_rule'
  tag stig_id: 'SRG-APP-000343-MFP-000091'
  tag gtitle: 'SRG-APP-000343-MFP-000091'
  tag fix_id: 'F-74289r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
