control 'SV-24821' do
  title 'Sensitive data served by the DBMS should be protected by encryption when transmitted across the network.'
  desc 'Sensitive data served by the DBMS and transmitted across the network in clear text is vulnerable to unauthorized capture and review.'
  desc 'check', 'If no data is identified as being sensitive or classified by the Information Owner, in the System Security Plan or in the AIS Functional Architecture documentation, this check is Not a Finding.

If no identified sensitive or classified data requires encryption by the Information Owner in the System Security Plan and/or AIS Functional Architecture documentation, this check is Not a Finding.

If encryption requirements are listed and specify configuration at the host system or network device level, then review evidence that the configuration meets the specification.

It may be necessary to review network device configuration evidence or host communications configuration evidence.

If the evidence review does not meet the requirement or specification as listed in the System Security Plan, this is a Finding.'
  desc 'fix', 'Configure encryption of sensitive data served by the DBMS in accordance with the specifications provided in the System Security Plan and AIS Functional Architecture documentation.

Document acceptance of risk by the Information Owner where sensitive or classified data is not encrypted.

Have the IAO document assurance that the unencrypted sensitive or classified information is otherwise inaccessible to those who do not have Need-to-Know access to the data.'
  impact 0.7
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29385r1_chk'
  tag severity: 'high'
  tag gid: 'V-15104'
  tag rid: 'SV-24821r1_rule'
  tag stig_id: 'DG0167-ORACLE11'
  tag gtitle: 'Encryption of DBMS sensitive data in transit'
  tag fix_id: 'F-26410r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
