control 'SV-24775' do
  title 'Use of DBA accounts should be restricted to administrative activities.'
  desc 'Use of privileged accounts for non-administrative purposes puts data at risk of unintended or unauthorized loss, modification or exposure. In particular, DBA accounts if used for non-administration application development or application maintenance can lead to miss-assignment of privileges where privileges are inherited by object owners. It may also lead to loss or compromise of application data where the elevated privileges bypass controls designed in and provided by applications.'
  desc 'check', 'Review objects owned by custom DBA user accounts.

If any objects owned by DBA accounts are accessed by non-DBA users either directly or indirectly by other applications, this is a Finding.

Review documentation or instructions provided to DBAs to communicate proper and improper use of DBA accounts.

If such documentation does not exist or if DBAs do not indicate an understanding of this requirement, this is a Finding.'
  desc 'fix', 'Develop, document and implement policy and procedures for outlining the proper and improper use of DBA accounts.

The documentation should clearly state that DBA accounts are used to administer and maintain the database only.

DBA accounts are not to be used to create or alter application objects.

Application maintenance should always be performed by the application object owner or application administrator accounts.

Request acknowledgement of receipt of these restrictions by all users granted DBA responsibilities.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1254r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15632'
  tag rid: 'SV-24775r1_rule'
  tag stig_id: 'DG0124-ORACLE11'
  tag gtitle: 'DBA account use'
  tag fix_id: 'F-2624r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
