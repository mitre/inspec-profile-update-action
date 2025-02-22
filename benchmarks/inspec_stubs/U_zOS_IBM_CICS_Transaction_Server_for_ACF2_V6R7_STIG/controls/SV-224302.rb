control 'SV-224302' do
  title 'CICS system data sets are not properly protected.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Unauthorized access to CICS system data sets (i.e., product, security, and application libraries) could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(CICSRPT)

Since it is possible to have multiple CICS regions running on an LPAR, it is recommended that you go into the z/OS STIG Addendum and fill out all the information in the "CICS System Programmers Worksheet" for each CICS region running on your LPAR. It is recommended that you save this information for any other CICS vulnerabilities that will require it.

b)	WRITE and/or ALLOCATE access to CICS system data sets is restricted to systems programming personnel.

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'Review the access authorizations for CICS system data sets for each region.  Ensure they conform to the specifications below:

A CICS environment may include several data set types required for operation.  Typically they are CICS product libraries, which are usually included in the STEPLIB concatenation but may be found in DD DFHRPL.  CICS system data sets that can be identified with DFH DD statements, other product system data sets, and application program libraries. Restrict alter and update access to CICS program libraries and all system data sets to systems programmers only.  Other access must be documented and approved by the IAO.  The site may determine access to application data sets included in the DD DFHRPL and CICS region startup JCL according to need.  Ensure that procedures are established; documented, and followed that prevents the introduction of unauthorized or untested application programs into production application systems.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25979r520226_chk'
  tag severity: 'medium'
  tag gid: 'V-224302'
  tag rid: 'SV-224302r520228_rule'
  tag stig_id: 'ZCIC0010'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25967r520227_fix'
  tag 'documentable'
  tag legacy: ['SV-7978', 'V-7516']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
