control 'SV-7027' do
  title 'Scan to a file share is enabled but the file shares do not have the appropriate discretionary access control list in place.'
  desc 'Without appropriate discretionary access controls unauthorized individuals may read the scanned data.  This can lead to a compromise of sensitive data.
The SA will ensure file shares have the appropriate discretionary access control list in place if scan to a file share is enabled.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that file shares have the appropriate discretionary access control list in place if scan to a file share is enabled.'
  desc 'fix', 'Create the appropriate discretionary access control list for file shares if scan to a file share is enabled.'
  impact 0.3
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3017r1_chk'
  tag severity: 'low'
  tag gid: 'V-6802'
  tag rid: 'SV-7027r1_rule'
  tag stig_id: 'MFD07.003'
  tag gtitle: 'MFD Scan Discretionary Access Control'
  tag fix_id: 'F-6476r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
