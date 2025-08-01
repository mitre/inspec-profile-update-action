control 'SV-217306' do
  title 'The Juniper router must be configured to automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the router configuration to determine if it audits account creation. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

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

If account creation is not audited, this is a finding.'
  desc 'fix', 'Configure the router to audit the creation of accounts. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

[edit system]
set syslog file LOG_FILE change-log info

Note: The parameter “any” can be in place of “change-log” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18533r296496_chk'
  tag severity: 'medium'
  tag gid: 'V-217306'
  tag rid: 'SV-217306r395484_rule'
  tag stig_id: 'JUNI-ND-000090'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-18531r296497_fix'
  tag 'documentable'
  tag legacy: ['SV-101195', 'V-91095']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
