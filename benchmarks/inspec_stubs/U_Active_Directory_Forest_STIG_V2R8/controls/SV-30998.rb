control 'SV-30998' do
  title 'Changes to the AD schema must be subject to a documented configuration management process.'
  desc 'Poorly planned or implemented changes to the AD schema could cause the applications that rely on AD (such as web and database servers) to operate incorrectly or not all.

Improper changes to the schema could result in changes to AD objects that are incompatible with correct operation of the Windows domain controller and the domain clients. This could cause outages that prevent users from logging on or accessing Windows server resources across multiple hosts.'
  desc 'check', '1. Interview the IAO.

2. Obtain a copy of the site’s configuration management procedures documentation.

3. Verify that there is a local policy that requires changes to the directory schema to be processed through a configuration management process. This applies to directory schema changes whether implemented in a database or other types of files. For AD, this refers to changes to the AD schema.

4. If there is no policy that requires changes to the directory schema to be processed through a configuration management process, then this is a finding.'
  desc 'fix', 'Document and implement a policy to ensure that changes to the AD schema are subject to a configuration management process.'
  impact 0.3
  ref 'DPMS Target Active Directory Forest'
  tag check_id: 'C-7684r2_chk'
  tag severity: 'low'
  tag gid: 'V-8527'
  tag rid: 'SV-30998r3_rule'
  tag stig_id: 'DS00.0100_AD'
  tag gtitle: 'Schema Change Configuration Management'
  tag fix_id: 'F-8056r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCPR-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
