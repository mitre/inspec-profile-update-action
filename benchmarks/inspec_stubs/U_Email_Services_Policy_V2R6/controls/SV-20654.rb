control 'SV-20654' do
  title 'Email audit trails must be reviewed daily.'
  desc 'Access to email servers and software are logged to establish a history of actions taken in the system. Unauthorized access or use of the system could indicate an attempt to bypass established permissions. 

Reviewing the log history can lead to discovery of unauthorized access attempts. Reviewing the logs daily helps to ensure prompt attention is given to any suspicious activities discovered therein.'
  desc 'check', 'Review the audit trail review procedures in the EDSP.  Examine artifacts of log reviews (results) and review frequency.

If Audit trail review procedures and evidence of review results exist, this is not a finding.'
  desc 'fix', 'Document audit record review procedures in the EDSP.  Implement audit record daily reviews as documented.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22677r5_chk'
  tag severity: 'low'
  tag gid: 'V-18869'
  tag rid: 'SV-20654r3_rule'
  tag stig_id: 'EMG3-037 EMail'
  tag gtitle: 'EMG3-037 Audit Trail Reviews'
  tag fix_id: 'F-19573r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECAT-1'
end
