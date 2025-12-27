control 'SV-225306' do
  title 'Audit data must be reviewed on a regular basis.'
  desc 'To be of value, audit logs from critical systems must be reviewed on a regular basis.  Critical systems should be reviewed on a daily basis to identify security breaches and potential weaknesses in the security structure.  This can be done with the use of monitoring software or other utilities for this purpose.'
  desc 'check', 'Determine whether audit logs are reviewed on a predetermined schedule.  If audit logs are not reviewed on a regular basis, this is a finding.'
  desc 'fix', 'Review audit logs on a predetermined scheduled.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27005r471260_chk'
  tag severity: 'medium'
  tag gid: 'V-225306'
  tag rid: 'SV-225306r569185_rule'
  tag stig_id: 'WN12-AU-000200'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-26993r471261_fix'
  tag 'documentable'
  tag legacy: ['SV-51561', 'V-36670']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
