control 'SV-101215' do
  title 'The Juniper router must be configured to generate audit records when successful/unsuccessful attempts to logon with access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below will log all logon attempts.

   syslog {
        file LOG_FILE {
            authorization info;
        }
    }

Note: The parameter "any" can be in place of "authorization" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host 10.1.58.2 {
            any info;
        }
    }
}

If the router is not configured to generate audit records when successful/unsuccessful attempts to logon, this is a finding.'
  desc 'fix', 'Configure the router to log all logon attempts as shown in the example below.

[edit system]
set syslog file LOG_FILE authorization info

Note: The parameter "any" can be in place of "authorization" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90269r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91115'
  tag rid: 'SV-101215r1_rule'
  tag stig_id: 'JUNI-ND-000250'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-97313r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
