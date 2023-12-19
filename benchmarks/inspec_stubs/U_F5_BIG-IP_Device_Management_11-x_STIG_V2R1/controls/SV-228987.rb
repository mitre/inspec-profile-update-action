control 'SV-228987' do
  title 'The BIG-IP appliance must be configured to use NIAP evaluated cryptographic mechanisms to protect the integrity of audit information at rest.'
  desc 'Audit records may be tampered with. If the integrity of audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

Protection of audit records and audit data, including audit configuration settings, is of critical importance. Cryptographic mechanisms are the industry-established standard used to protect the integrity of audit data. An example of a cryptographic mechanism is the computation and application of a cryptographic-signed hash using asymmetric cryptography.

This requirement is not intended to cause a new cryptographic hash to be generated every time a record is added to a log file.'
  desc 'check', 'Verify the BIG-IP appliance is configured to off-load audit information to a logging system that uses NIAP evaluated cryptographic mechanisms to protect the integrity of audit information at rest. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Remote Logging.

Verify a syslog destination is configured that uses NIAP evaluated cryptographic mechanisms to protect the integrity of audit information at rest.

If the BIG-IP appliance does not off-load audit information to a remote logging system that uses NIAP evaluated cryptographic mechanisms to protect the integrity of audit information at rest, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to off-load audit information to a system that uses NIAP evaluated cryptographic mechanisms to protect the integrity of audit information at rest.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31302r518006_chk'
  tag severity: 'medium'
  tag gid: 'V-228987'
  tag rid: 'SV-228987r557520_rule'
  tag stig_id: 'F5BI-DM-000087'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31279r518007_fix'
  tag 'documentable'
  tag legacy: ['V-60137', 'SV-74567']
  tag cci: ['CCI-000366', 'CCI-001350']
  tag nist: ['CM-6 b', 'AU-9 (3)']
end
