control 'SV-217345' do
  title 'The Juniper router must be configured to generate audit records when successful/unsuccessful logon attempts occur.'
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

If the router is not configured to generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the router to generate audit records when successful/unsuccessful logon attempts occur as shown in the example below.

[edit system]
set syslog file LOG_FILE authorization info

Note: The parameter "any" can be in place of authorization" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host x.x.x.x any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18572r296613_chk'
  tag severity: 'medium'
  tag gid: 'V-217345'
  tag rid: 'SV-217345r879874_rule'
  tag stig_id: 'JUNI-ND-001250'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-18570r296614_fix'
  tag 'documentable'
  tag legacy: ['SV-101279', 'V-91179']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
