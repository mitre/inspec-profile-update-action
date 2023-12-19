control 'SV-101209' do
  title 'The Juniper router must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the router configuration to determine if it logs configuration changes as shown in the following example: 

system {
    syslog {
        file LOG_FILE {
            change-log info;
        }
    }
}

Note: The parameter “any” can be in place of “change-log” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

system {
   syslog {
        host 10.1.58.2 {
            any info;
        }
        file LOG_FILE {
            change-log info;
        }
        console {
            any error;
        }
    }
}

If configuration change activity is not logged, this is a finding.'
  desc 'fix', 'Configure the router to log configuration changes as shown in the following example: 

set syslog file LOG_FILE change-log info

Note: The parameter “any” can be in place of “change-log” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90263r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91109'
  tag rid: 'SV-101209r1_rule'
  tag stig_id: 'JUNI-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-97307r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
