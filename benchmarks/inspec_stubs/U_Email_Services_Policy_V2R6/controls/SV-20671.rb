control 'SV-20671' do
  title 'Email audit records must be retained for 1 year.'
  desc 'Audit data retention serves as a history that can aid in determining actions executed by users and administrators. Reasons for such research include both malicious actions that may have been perpetrated, as well as legal evidence that might be needed for proof of activity. 

Audit data records are required to be retained for a period of 1 year.'
  desc 'check', 'Access EDSP documentation that describes data retention for audit records. Examine artifacts that demonstrate audit data retention for a period of 1 year. 

If email audit records are retained for required time period (1 year), this is not a finding.'
  desc 'fix', 'Create a process that details email audit record retention for required time period of 1 year.  Document the process in the EDSP.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22681r3_chk'
  tag severity: 'medium'
  tag gid: 'V-18879'
  tag rid: 'SV-20671r3_rule'
  tag stig_id: 'EMG3-071 EMail'
  tag gtitle: 'EMG3-071 Audit Data Retention'
  tag fix_id: 'F-19478r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECRR-1'
end
