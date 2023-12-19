control 'SV-217329' do
  title 'The Juniper router must be configured to automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Review the router configuration to determine if it audits the enabling of accounts. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

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

If the enabling of accounts is not audited, this is a finding.

Note: Accounts can be disabled by changing the assigned class to unauthorized (no permissions). Hence, accounts can be enabled by changing the assigned class for the user to a class other than unauthorized.'
  desc 'fix', 'Configure the router to audit the enabling of accounts. This requirement can be met by ensuring that configuration changes are logged as shown in the following example: 

set syslog file LOG_FILE change-log info

Note: The parameter “any” can be in place of “change-log” as this will log everything. Also, a syslog server can be configured in addition to or in lieu of logging to a file as shown in the example below.

set syslog host 10.1.58.2 any info

Note: Accounts can be disabled by changing the assigned class to unauthorized (no permissions). Hence, accounts can be enabled by changing the assigned class for the user to a class other than unauthorized.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18556r296565_chk'
  tag severity: 'medium'
  tag gid: 'V-217329'
  tag rid: 'SV-217329r855872_rule'
  tag stig_id: 'JUNI-ND-000870'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-18554r296566_fix'
  tag 'documentable'
  tag legacy: ['SV-101245', 'V-91145']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
