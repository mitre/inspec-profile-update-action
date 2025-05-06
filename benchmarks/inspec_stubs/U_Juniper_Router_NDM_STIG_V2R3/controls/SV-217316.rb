control 'SV-217316' do
  title 'The Juniper router must be configured to generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below will log all configuration changes.

   syslog {
        file LOG_FILE {
            change-log info;
        }
    }

Note: The parameter "any" can be in place of "change-log" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host 10.1.58.2 {
            any info;
        }
    }
}

If the router is not configured to generate audit records of configuration changes, this is a finding.'
  desc 'fix', 'Configure the router to log all configuration changes as shown in the example below.

[edit system]
set syslog file LOG_FILE change-log info

Note: The parameter "any" can be in place of "change-log" as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18543r296526_chk'
  tag severity: 'medium'
  tag gid: 'V-217316'
  tag rid: 'SV-217316r879569_rule'
  tag stig_id: 'JUNI-ND-000330'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-18541r296527_fix'
  tag 'documentable'
  tag legacy: ['SV-101217', 'V-91117']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
