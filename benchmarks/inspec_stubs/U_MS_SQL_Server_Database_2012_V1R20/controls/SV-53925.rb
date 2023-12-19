control 'SV-53925' do
  title 'SQL Server job/batch queues must be reviewed regularly to detect unauthorized SQL Server job submissions.'
  desc 'When dealing with unauthorized SQL Server job submissions, it should be noted any unauthorized job submissions to SQL Server job/batch queues can potentially have significant effects on the overall security of the system.

If SQL Server were to allow any user to make SQL Server job/batch queue submissions, then those submissions might lead to a compromise of system integrity and/or data. This requirement is contingent upon the SQL Server job/batch queue being review regularly for unauthorized submissions.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to submit SQL Server jobs. Job/batch queue submissions must adhere to an organization-defined job submission process. 

Unmanaged changes that occur to SQL Server job/batch queues can lead to a compromised system.'
  desc 'check', 'Check system documentation for procedures that are regularly implemented in an effort to detect unauthorized SQL Server job submissions.

If procedures that are regularly implemented are not documented in the system documentation, this is a finding.

If the procedures are not implemented regularly or do not detect for unauthorized SQL Server job submissions, this is a finding.

Review Stored Procedures that are able to automatically execute jobs scheduled to start automatically at system startup by running the following query:
SELECT name
  FROM master.sys.procedures
 WHERE is_auto_executed = 1

If any Stored Procedures listed are not documented as authorized, this is a finding.  

Review the SQL Server job history by running the following query:

SELECT *   FROM msdb.dbo.sysjobhistory 


If any jobs listed are not documented as authorized, this is a finding.'
  desc 'fix', 'Document procedures, within the system documentation, that detect for unauthorized SQL Server job submissions.

Develop and implement procedures to detect for unauthorized SQL Server job submissions of Stored Procedures that are automatically executed and Agent jobs that are enabled.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47937r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41399'
  tag rid: 'SV-53925r2_rule'
  tag stig_id: 'SQL2-00-023500'
  tag gtitle: 'SRG-APP-999999-DB-000209'
  tag fix_id: 'F-46825r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
