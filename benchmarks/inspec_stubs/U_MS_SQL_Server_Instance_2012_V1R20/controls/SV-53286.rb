control 'SV-53286' do
  title 'SQL Server must recover to a known state that is verifiable.'
  desc 'Application recovery and reconstitution constitutes executing an information system contingency plan comprising activities that restore essential missions and business functions.

SQL Server utilizes transaction-based processing and is a good example of information systems that are transaction-based. Transaction rollback and transaction journaling are examples of mechanisms supporting transaction recovery.

SQL Server may be vulnerable to use of compromised data or other critical files during recovery. Use of compromised files could introduce maliciously altered application code, relaxed security settings, or loss of data integrity. SQL Server mechanisms must be configured to protect all files that could compromise the system or its data during a SQL Server recovery.'
  desc 'check', "Obtain the SQL Server recovery procedures and technical system features to determine if mechanisms exist and are in place to specify use of trusted files during SQL Server recovery.

If recovery procedures do not exist or are not sufficient to ensure recovery is done in a secure and verifiable manner, this is a finding.

Check the configurations of all transaction log files that are enabled by running the following SQL Server query:

EXEC sp_MSforeachdb
'
SELECT ''?'' AS ''database name''
       , name AS ''log file name''
       , physical_name AS ''log file location and name''
       , state_desc
       , size
       , max_size
       , growth
       , is_percent_growth
  FROM [?].sys.database_files
 WHERE type_desc = ''LOG''
   AND state = 0;
'
; 

If any transaction log files are not configured correctly for size, max_size, and growth to log sufficient transaction information, this is a finding."
  desc 'fix', 'Implement SQL Server recovery procedures to ensure the use of trusted files during SQL Server recovery.

Modify the parameters for the transaction log file(s) for the system databases:

Navigate to SQL Server Management Studio >> Object Explorer >> <SQL Server instance name> >> Databases >> System Databases >> right-click on <system database name> >> Properties >> Files.

OR

Modify the parameters for the transaction log file(s) for application databases:

Navigate to SQL Server Management Studio >> Object Explorer >> <SQL Server instance name> >> Databases >> right-click on <user-defined database name> >> Properties >> Files.

THEN

Define additional space for the transaction log file, or extra transaction log files, as necessary.

To modify Initial Size (MB), click in the "Initial Size (MB)" field for the log file in question, then edit the value.

To modify Autogrowth, click on the "Autogrowth/Maxsize" button for the log file in question, choose "In Percent" or "In Megabytes", enter value, and then click OK.

To modify Maximum File Size, click on the "Autogrowth/Maxsize" button for the log file in question, choose "Limited to (MB)", enter value, and then click OK. Do not select "Unlimited".'
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47587r3_chk'
  tag severity: 'high'
  tag gid: 'V-40932'
  tag rid: 'SV-53286r4_rule'
  tag stig_id: 'SQL2-00-017500'
  tag gtitle: 'SRG-APP-000144-DB-000101'
  tag fix_id: 'F-46214r6_fix'
  tag 'documentable'
  tag cci: ['CCI-000553']
  tag nist: ['CP-10 (2)']
end
