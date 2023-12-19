control 'SV-70913' do
  title 'The operating system must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the operating system, the operating system must also generate audit records that identify sources of events. Sources of operating system events include, but are not limited to, processes and services.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish the source of the events. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish the source of the events.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57223r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56653'
  tag rid: 'SV-70913r1_rule'
  tag stig_id: 'SRG-OS-000040-GPOS-00018'
  tag gtitle: 'SRG-OS-000040-GPOS-00018'
  tag fix_id: 'F-61549r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
