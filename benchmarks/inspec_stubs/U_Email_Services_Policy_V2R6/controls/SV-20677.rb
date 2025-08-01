control 'SV-20677' do
  title 'Email backup and recovery data must be protected.'
  desc 'All automated information systems are at risk of data loss due to disaster or compromise. Failure to provide adequate protection to the backup and recovery data exposes it to risk of potential theft or damage that may ultimately prevent a successful restoration, should the need become necessary. Adequate protection ensures that backup components can be used to provide transparent or easy recovery from losses or operations outages.

Backup files need the same protections against unauthorized access when stored on backup media as when online and actively in use by the email system. Included in this category are physical media, online configuration file copies, and any user data that may need to be restored.'
  desc 'check', 'Access EDSP documentation that describes protections for the Backup and Recovery data. 

If email backup and recovery data and processes are restricted to authorized users and groups, this is not a finding.'
  desc 'fix', 'Document the authorized backup and recovery users and groups in the EDSP.  Create access restrictions to the authorized staff for email services backup and restore data.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22536r3_chk'
  tag severity: 'medium'
  tag gid: 'V-18882'
  tag rid: 'SV-20677r3_rule'
  tag stig_id: 'EMG3-009 EMail'
  tag gtitle: 'EMG3-009 Restrict Access to Backup/ Recovery Data'
  tag fix_id: 'F-19579r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'COBR-1'
end
