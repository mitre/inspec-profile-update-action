control 'SV-217347' do
  title 'The Juniper router must be configured to generate log records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the examples below.

   syslog {
        file LOG_FILE {
            authorization info;
        }
    }

Note: The parameter "any" can be in place of "authorization" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host x.x.x.x {
            any info;
        }
    }

If the router is not configured to generate log records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the router to generate log records when concurrent logons from different workstations occur as shown in the example below.

[edit system]
set syslog file LOG_FILE authorization info

Note: The parameter "any" can be in place of authorization" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host x.x.x.x any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18574r296619_chk'
  tag severity: 'medium'
  tag gid: 'V-217347'
  tag rid: 'SV-217347r400852_rule'
  tag stig_id: 'JUNI-ND-001280'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-18572r296620_fix'
  tag 'documentable'
  tag legacy: ['SV-101283', 'V-91183']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
