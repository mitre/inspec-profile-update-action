control 'SV-53304' do
  title 'SQL Server must support the employment of automated mechanisms supporting the auditing of the enforcement actions.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals are allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 

Access restrictions for change also include software libraries. 

Examples of access restrictions include: physical access controls (such as locks and access cards), logical access controls (such as ACLs), automated auditing (logging) of logical access, workflow automation, media libraries, abstract layers (e.g., changes are implemented into a third-party interface rather than directly into the information system component), and change windows (e.g., changes occur only during specified times, making unauthorized changes outside the window easy to discover).  

This requirement focuses on the auditing aspect of the protections.'
  desc 'check', 'Verify that Files and Folders that are part of the SQL Server 2012 Installation have auditing enabled.

Right click the root folder of the SQL Server installation.  Typically, this is at <drive>:\\Program Files\\Microsoft SQL Server\\.  Select Properties. 

Click on the Security tab

Click on the Advanced button

Click on the Auditing tab

If "Everyone" is not listed in the "Name" column, this is a finding.

If "This folder, subfolders and files" is not listed in the "Apply To" column, this is a finding.

When "Everyone" ... " is listed, select the "Everyone" row and click on the Edit button.

If either the Successful or Failed checkbox is not selected for any of the following access types, this is a finding:
    Traverse folder/execute file 
    List folder/read data
    Read attributes
    Read extended attributes
    Create files/write data
    Create folders/append data
    Write attributes
    Write extended attributes
    Delete
    Read permissions'
  desc 'fix', 'Navigate to Advanced Security Settings by selecting Properties > Security > Advanced > Auditing > Continue.

Where "Everyone" is missing from the "Name" column, click the Add button; type "Everyone" in the object names box; click the OK button.  The Auditing Entry dialog opens.

Where "Everyone" is in the "Name" column, select that row and click on the Edit button.  The Auditing Entry dialog opens.

In the Auditing Entry dialog, set "Apply onto" to "This folder, subfolders and files".

In the Auditing Entry dialog, select both the Successful and the Failed checkbox for each of the following access types, where not already selected:
    Traverse folder/execute file 
    List folder/read data
    Read attributes
    Read extended attributes
    Create files/write data
    Create folders/append data
    Write attributes
    Write extended attributes
    Delete
    Read permissions

Click OK, OK, OK, OK to save the new settings and exit the dialog boxes.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47605r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40950'
  tag rid: 'SV-53304r3_rule'
  tag stig_id: 'SQL2-00-014700'
  tag gtitle: 'SRG-APP-000130-DB-000088'
  tag fix_id: 'F-46232r5_fix'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
