control 'SV-217349' do
  title 'The Juniper router must be configured to generate log records for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The example below illustrates how selected events can be logged.

   syslog {
        file LOG_FILE {
            authorization info;
            security info;
            firewall info;
            change-log info;
        }
    }

Note: A syslog server can be configured in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host x.x.x.x {
            authorization info;
            security info;
            firewall info;
            change-log info;
        }
    }

If the router is not configured to generate log records for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Configure the router to generate log records for a locally developed list of auditable events as shown in the example below.

[edit system]
set syslog file LOG_FILE authorization info
set syslog file LOG_FILE security info
set syslog file LOG_FILE firewall info
set syslog file LOG_FILE change-log info

Note: A syslog server can be configured in lieu of logging to a file as shown in the example below.

set syslog host x.x.x.x authorization info
set syslog host x.x.x.x security info
set syslog host x.x.x.x firewall info
set syslog host x.x.x.x change-log info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18576r296625_chk'
  tag severity: 'medium'
  tag gid: 'V-217349'
  tag rid: 'SV-217349r879887_rule'
  tag stig_id: 'JUNI-ND-001340'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-18574r296626_fix'
  tag 'documentable'
  tag legacy: ['SV-101287', 'V-91187']
  tag cci: ['CCI-000366', 'CCI-000169']
  tag nist: ['CM-6 b', 'AU-12 a']
end
