control 'SV-217346' do
  title 'The Juniper router must be configured to generate log records for privileged activities.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example configurations below.

syslog {
        file LOG_FILE {
            change-log info;
            interactive-commands info;
        }
    }

Note: The parameter "any" can be in place of "change-log" and “interactive-commands” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host x.x.x.x {
            any info;
        }
    }

If the router is not configured to generate log records for privileged activities, this is a finding.'
  desc 'fix', 'Configure the router to generate log records for privileged activities as shown in the example below.

[edit system]
set syslog file LOG_FILE change-log info
set syslog file LOG_FILE interactive-commands info

Note: The parameter "any" can be in place of "change-log" and “interactive-commands” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host x.x.x.x any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18573r296616_chk'
  tag severity: 'medium'
  tag gid: 'V-217346'
  tag rid: 'SV-217346r879875_rule'
  tag stig_id: 'JUNI-ND-001260'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-18571r296617_fix'
  tag 'documentable'
  tag legacy: ['SV-101281', 'V-91181']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
