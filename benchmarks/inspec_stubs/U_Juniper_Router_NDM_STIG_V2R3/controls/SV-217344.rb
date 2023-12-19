control 'SV-217344' do
  title 'The Juniper router must be configured to generate log records when administrator privileges are deleted.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

   syslog {
        file LOG_FILE {
            change-log info;
        }
    }

Note: The parameter "any" can be in place of "change-log" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host x.x.x.x {
            any info;
        }
    }

If the router is not configured to generate log records when administrator privileges are deleted, this is a finding.'
  desc 'fix', 'Configure the router to generate log records when administrator privileges are deleted as shown in the example below.

[edit system]
set syslog file LOG_FILE change-log info

Note: The parameter "any" can be in place of "change-log" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host x.x.x.x any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18571r296610_chk'
  tag severity: 'medium'
  tag gid: 'V-217344'
  tag rid: 'SV-217344r879870_rule'
  tag stig_id: 'JUNI-ND-001240'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-18569r296611_fix'
  tag 'documentable'
  tag legacy: ['SV-101277', 'V-91177']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
