control 'SV-101197' do
  title 'The Juniper router must be configured to automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Review the router configuration to determine if it audits account modification. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

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

If account modification is not audited, this is a finding.'
  desc 'fix', 'Configure the router to audit the modification of accounts. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

[edit system]
set syslog file LOG_FILE change-log info

Note: The parameter “any” can be in place of “change-log” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90251r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91097'
  tag rid: 'SV-101197r1_rule'
  tag stig_id: 'JUNI-ND-000100'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-97295r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
