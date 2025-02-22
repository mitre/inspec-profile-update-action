control 'SV-237968' do
  title 'The IBM z/VM system administrator must develop procedures maintaining information system operation in the event of anomalies.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the system.'
  desc 'check', 'Ask the system administrator for a procedure to notify appropriate personnel in the event of system anomalies or failure.

If there is no procedure for notification and resolution or they are not documented and on file with the ISSO, this is a finding.'
  desc 'fix', 'Develop a procedure for the notification and resolution of operation information system operation anomalies.

Assure that procedures are documented and filed with the ISSO/ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41178r649742_chk'
  tag severity: 'medium'
  tag gid: 'V-237968'
  tag rid: 'SV-237968r649744_rule'
  tag stig_id: 'IBMZ-VM-002380'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41137r649743_fix'
  tag 'documentable'
  tag legacy: ['SV-93689', 'V-78983']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
