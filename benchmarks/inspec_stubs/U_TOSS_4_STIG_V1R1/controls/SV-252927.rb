control 'SV-252927' do
  title 'The TOSS operating system must be configured to preserve log records from failure events.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.'
  desc 'check', 'Verify the rsyslog service is enabled and active with the following commands:

$ sudo systemctl is-enabled rsyslog

enabled

$ sudo systemctl is-active rsyslog

active

If the service is not "enabled" and "active", this is a finding.

If "rsyslog" is not enabled, ask the System Administrator how system error logging is performed on the system. If there is no evidence of system logging being performed on the system, this is a finding.'
  desc 'fix', 'Start and enable the rsyslog service with the following commands:

$ sudo systemctl start rsyslog.service

$ sudo systemctl enable rsyslog.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56380r824103_chk'
  tag severity: 'medium'
  tag gid: 'V-252927'
  tag rid: 'SV-252927r824105_rule'
  tag stig_id: 'TOSS-04-010170'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-56330r824104_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
