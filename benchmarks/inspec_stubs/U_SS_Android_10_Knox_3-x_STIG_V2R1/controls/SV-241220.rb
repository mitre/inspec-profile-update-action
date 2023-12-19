control 'SV-241220' do
  title 'Samsung Android must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events for which the system must generate an audit record.

SFR ID: FAU_GEN.1.1 #8'
  desc 'check', 'Review Samsung Android device configuration settings to confirm that Audit logging is enabled.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on the management tool Administration Console only.

****

Method #1: KPE Audit logging

On the management tool, for the device KPE audit log section, verify that "Audit log" is set to "Enable".

If on the management tool the "Audit log" is not set to "Enable", this is a finding.

****

Method #2: AE Audit logging

On the management tool, do the following:
1. In the device restrictions section, verify that "Security logging" is set to "Enable".
2. In the device restrictions section, verify that "Network logging" is set to "Enable".

If on the management tool both "Security logging" and "Network logging are not set to "Enable", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable audit logging.

Do one of the following:
- Method #1: KPE Audit logging
- Method #2: AE Audit logging

****

Method #1: KPE Audit logging

On the management tool, in the device KPE audit log section, set "Audit log" to "Enable".

****

Method #2: AE Audit logging

On the management tool, do the following:
1. In the device restrictions section, set "Security logging" to "Enable".
2. In the device restrictions section, set "Network logging" to "Enable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44496r680299_chk'
  tag severity: 'medium'
  tag gid: 'V-241220'
  tag rid: 'SV-241220r680301_rule'
  tag stig_id: 'KNOX-10-009500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44455r680300_fix'
  tag 'documentable'
  tag legacy: ['SV-109073', 'V-99969']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
