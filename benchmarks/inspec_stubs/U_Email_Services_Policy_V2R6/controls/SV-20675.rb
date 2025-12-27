control 'SV-20675' do
  title 'The email backup and recovery strategy must be documented and tested on an INFOCON compliant frequency.'
  desc 'A disaster recovery plan exists that provides for the smooth transfer of all mission or business essential functions to an alternate site for the duration of an event with little or no loss of operational continuity.
 
The backup and recovery plan should include business recovery, system contingency, facility disaster recovery plans and plan acceptance.'
  desc 'check', 'Access the disaster recovery documentation that describes the backup and recovery strategy for the email servers. The documentation should detail specifically what files and data stores are saved, including the frequency and schedules of the saves (as required by INFOCON levels), and recovery plans (should they become necessary). 

The recovery plan should also state a periodic recovery rehearsal to ensure the backup strategy is sound. 

If Email Backup and Recovery strategy is documented and periodically tested, this is not a finding.'
  desc 'fix', 'Document the Email Backup and Recovery Strategy site Disaster Recovery Plan, with components, locations and directions, and test according to INFOCON frequency requirements.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22534r4_chk'
  tag severity: 'low'
  tag gid: 'V-18881'
  tag rid: 'SV-20675r3_rule'
  tag stig_id: 'EMG3-005 EMail'
  tag gtitle: 'EMG3-005 Backup and Recovery Strategy'
  tag fix_id: 'F-19578r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'CODP-1'
end
