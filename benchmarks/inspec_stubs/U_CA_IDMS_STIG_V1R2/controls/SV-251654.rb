control 'SV-251654' do
  title 'CA IDMS must use pervasive encryption to cryptographically protect the confidentiality and integrity of all information at rest in accordance with data owner requirements.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.

'
  desc 'check', %q(If this CA IDMS has no requirement for confidentiality and integrity of all information at rest in accordance with the data owners requirements, this not applicable.

If required files are not defined as a VSAM dataset this is a finding.

Perform the following for the VSAM dataset

1. LISTC ENT('dsn') ALL"  

Where "dsn" is the DSNAME of the cluster; review the ATTRIBUTES section of the output to ensure that the database is defined as NONINEXED (the cluster is an ESDS). If not, this is a finding.

2. In the IDCAMS LISTC output, look for the SMSDATA section. If none is found this is a finding.  
Otherwise, find the "DATACLASS" name and query the systems programmer to ensure that the SMS data class specifies "Extended Format" but does not specify "Extended Addressing". If not, this is a finding.

3.  In the IDCAMS LISTC output: 
Find the "STORAGECLASS" and query the systems programmer to ensure it supports extended format VSAM dataset. If not, this is a finding.

4. Confirm that the database(s) have a data set key label. Places to check for a data set key label:
  a. In the SMS data class definition by reviewing the entry for the appropriate data class in ISMF
  b. In the output of an IDCAMS LISTC in the ENCRYPTIONDATA section.  If "DATA SET ENCRYPTION" is "YES", then the label will be displayed after "DATA SET KEY LABEL".  
  c. The key label may be assigned through the ESM. Query the security team to determine if this is the case. 

5. The database(s) must be defined in the DMCL as "VSAM".  Run "IDMSLOOK" to print the contents of the DMCL and look for the desired database(s). If the TYPE column is not "VSAM", this is a finding.)
  desc 'fix', "Enable pervasive encryption to protect data at rest:

1. Query system programmers, DBAs, and security team members as needed to determine SMS data and storage classes and data set key labels to use
2. Convert the desired database to a VSAM cluster.  
   a. If necessary, expand the page size of the area(s) current files. The optimal page size is eight bytes less than the VSAM control interval size.
   b. Alter the file definition to change its access method and then generate, punch, and link all DMCLs in which the file's segment is included. Optionally, specify a new database name or other location 
       information
   c. Allocate the new database file(s).

3. Modify the CV and batch JCL to reference the new VSAM data set(s).

4. Using the appropriate OS utility, copy the original database file(s) to the new, VSAM database file(s). 

Note that the actual data encryption takes place when the database is written to or read from."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55092r807836_chk'
  tag severity: 'medium'
  tag gid: 'V-251654'
  tag rid: 'SV-251654r855291_rule'
  tag stig_id: 'IDMS-DB-000930'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-55046r855290_fix'
  tag satisfies: ['SRG-APP-000428-DB-000386', 'SRG-APP-000429-DB-000387', 'SRG-APP-000231-DB-000154']
  tag 'documentable'
  tag cci: ['CCI-000119', 'CCI-002476']
  tag nist: ['AU-1 c 1', 'SC-28 (1)']
end
