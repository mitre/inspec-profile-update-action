control 'SV-101285' do
  title 'The Juniper router must be configured to off-load log records onto a different system than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

system {
   syslog {
        host x.x.x.x {
            any info;
        }
    }

If the router is not configured to off-load log records onto a different system than the system being audited, this is a finding.'
  desc 'fix', 'Configure the router to send log records to a syslog server as shown in the example below.

[edit system]
set syslog host x.x.x.x any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90339r3_chk'
  tag severity: 'medium'
  tag gid: 'V-91185'
  tag rid: 'SV-101285r1_rule'
  tag stig_id: 'JUNI-ND-001300'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-97383r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
