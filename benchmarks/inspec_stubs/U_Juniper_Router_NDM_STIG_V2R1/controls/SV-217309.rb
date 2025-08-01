control 'SV-217309' do
  title 'The Juniper router must be configured to automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the router configuration to determine if it audits the deletion of accounts. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

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

If the deletion of accounts is not audited, this is a finding.'
  desc 'fix', 'Configure the router to audit the deletion of accounts. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

[edit system]
set syslog file LOG_FILE change-log info

Note: The parameter “any” can be in place of “change-log” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18536r296505_chk'
  tag severity: 'medium'
  tag gid: 'V-217309'
  tag rid: 'SV-217309r395493_rule'
  tag stig_id: 'JUNI-ND-000120'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-18534r296506_fix'
  tag 'documentable'
  tag legacy: ['SV-101201', 'V-91101']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
