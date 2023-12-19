control 'SV-13607' do
  title 'Configuration change logs and justification for changes are not maintained.'
  desc 'If changes are made to the configuration without documentation, it is often difficult to determine the root cause of an operational problem or understand the circumstances in which a security breach occurred.  Without adequate configuration change records, it is also more difficult for the IAO and other oversight personnel to track major activity, which is critical to information assurance.'
  desc 'check', 'The DNS configuration change log must note the date and time any DNS configuration files were modified and the business justification for that modification.  Unless the business justification is routinely so vague as to be meaningless (e.g., “user request” for every entry), the reviewer should not second-guess what constitutes an acceptable business rationale.

Instruction:  If there is no configuration change log, then this is a finding.  If there are such records, then entries must include the date and time of any change and the business rationale for the change.  Failure to include this information for any entry is a finding.'
  desc 'fix', 'The IAO should implement, maintain, and periodically check compliance with configuration management requirements.  The configuration change log should include, at a minimum, the date and time of any modifications to the DNS configuration files and the business justification for that modification.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3362r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13039'
  tag rid: 'SV-13607r1_rule'
  tag stig_id: 'DNS0140'
  tag gtitle: 'Configuration change logs are not maintained.'
  tag fix_id: 'F-4344r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
