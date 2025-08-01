control 'SV-87269' do
  title 'The Cassandra database logs must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Review the Cassandra Server settings to ensure logs are protected from unauthorized read access.

At the command prompt, execute the following command:

# ls -lL /storage/log/vcops/log/cassandra

If any file does not have permissions of "0640", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server logs to be protected from unauthorized read access.

At the command prompt, execute the following command:

# chmod 0640 /storage/log/vcops/log/cassandra/<file>

Replace <file> with any file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72637'
  tag rid: 'SV-87269r1_rule'
  tag stig_id: 'VROM-CS-000065'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-79039r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
