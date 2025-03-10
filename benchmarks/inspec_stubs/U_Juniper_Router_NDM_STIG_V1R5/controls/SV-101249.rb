control 'SV-101249' do
  title 'The Juniper router must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below will log all commands entered from the command line interface as well as log all configuration changes.
  
syslog {
        file LOG_FILE {
            interactive-commands;
            change-log info  
        }
    }

Note: The parameter "any" can be in place of configuring specific events as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host 10.1.58.2 {
            any info;
        }
    }

If the router is not configured to log all commands entered from the command line interface as well as log all configuration changes, this is a finding.'
  desc 'fix', 'Configure the router to log all commands entered from the command line interface as well as log all configuration changes as shown in the following example:

[edit system]
set syslog file LOG_FILE interactive-commands
set syslog file LOG_FILE change-log info

Note: The parameter "any" can be in place of configuring specific events as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90303r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91149'
  tag rid: 'SV-101249r1_rule'
  tag stig_id: 'JUNI-ND-000930'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-97347r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
