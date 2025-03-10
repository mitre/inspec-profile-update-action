control 'SV-219825' do
  title 'Oracle instance names must not contain Oracle version numbers.'
  desc 'Service names may be discovered by unauthenticated users. If the service name includes version numbers or other database product information, a malicious user may use that information to develop a targeted attack.'
  desc 'check', 'From SQL*Plus:

  select instance_name from v$instance;
  select version from v$instance;

If the instance name returned references the Oracle release number, this is a finding.

Numbers used that include version numbers by coincidence are not a finding.

The DBA should be able to relate the significance of the presence of a digit in the SID.'
  desc 'fix', 'Follow the instructions in Oracle MetaLink Note 15390.1 (and related documents) to change the SID for the database without re-creating the database to a value that does not identify the Oracle version.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21536r533014_chk'
  tag severity: 'medium'
  tag gid: 'V-219825'
  tag rid: 'SV-219825r879887_rule'
  tag stig_id: 'O121-BP-021300'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21535r533015_fix'
  tag 'documentable'
  tag legacy: ['SV-75903', 'V-61413']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
