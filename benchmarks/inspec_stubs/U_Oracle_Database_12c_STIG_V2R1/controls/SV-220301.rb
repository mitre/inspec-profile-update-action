control 'SV-220301' do
  title 'The DBMS must only generate error messages that provide information necessary for corrective actions without revealing organization-defined sensitive or potentially harmful information in error logs and administrative messages that could be exploited.'
  desc 'Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team.

The extent to which the application is able to identify and handle error conditions is guided by organizational policy and operational requirements. Sensitive information includes account numbers, social security numbers, and credit card numbers.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', "Check DBMS settings and custom database and application code to verify error messages do not contain information beyond what is needed for troubleshooting the issue.

If database errors contain PII data, sensitive business data, or information useful for identifying the host system, this is a finding.

Notes on Oracle's approach to this issue:  Out of the box, Oracle covers this. For example, if a user does not have access to a table, the error is just that the table or view does not exist. The Oracle database is not going to display a Social Security Number in an error code unless an application is programmed to do so.  Oracle applications will not expose the actual transactional data to a screen.  The only way Oracle will capture this information is to enable specific logging levels.  Custom code would require a review to ensure compliance."
  desc 'fix', 'Configure DBMS and custom database and application code not to divulge sensitive information or information useful for system identification in error information.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22016r392034_chk'
  tag severity: 'medium'
  tag gid: 'V-220301'
  tag rid: 'SV-220301r397843_rule'
  tag stig_id: 'O121-C2-019900'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-22008r392035_fix'
  tag 'documentable'
  tag legacy: ['SV-76281', 'V-61791']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
