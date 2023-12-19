control 'SV-223687' do
  title 'IBM RACF must limit all system PROCLIB data sets to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to the following for the PROCLIB data sets that contain the STCs and TSO logons from the following sources:

- MSTJCLxx member used during an IPL. The PROCLIB data sets are obtained from the IEFPDSI and IEFJOBS DD statements.

- PROCxx DD statements and JES2 Dynamic PROCLIBs. Where ‘xx’ is the PROCLIB entries for the STC and TSU JOBCLASS configuration definitions. 

Verify that the accesses to the above PROCLIB data sets are properly restricted. 

If the following guidance is true, this is not a finding.

If the ESM data set access authorizations restrict READ access to all authorized users, this is not a finding.

If the ESM data set access authorizations restrict WRITE and/or greater access to systems programming personnel, this is not a finding.'
  desc 'fix', 'Configure ESM dataset rules to restrict all WRITE and/or greater access to all PROCLIBs referenced in the Master JCL and JES2 or JES3 procedure for started tasks (STCs) and TSO logons to systems programming personnel only.

Suggestion on how to update system to be compliant with this vulnerability:

NOTE: All examples are only examples and may not reflect your operating environment.

Obtain only the PROCLIB data sets that contain STC and TSO procedures. The data sets to be reviewed are obtained using the following steps:

- All data sets contained in the MSTJCLxx member in the DD statement concatenation for IEFPDSI and IEFJOBS.
- The data set in the PROCxx DD statement concatenation that are within the JES2 procedure or identified in the JES2 dynamic PROCLIB definitions. The specific PROCxx DD statement that is used is obtained from the PROCLIB entry for the JOBCLASSes of STC and TSU. The following is what data sets the process will obtain for analysis:

MSTJCL00

//MSTJCL00 JOB MSGLEVEL=(1,1),TIME=1440 
//EXEC PGM=IEEMB860,DPRTY=(15,15) 
//STCINRDR DD SYSOUT=(A,INTRDR) 
//TSOINRDR DD SYSOUT=(A,INTRDR) 
//IEFPDSI DD DSN=SYS3.PROCLIB,DISP=SHR <<===
//DD DSN=SYS2.PROCLIB,DISP=SHR <<===
//DD DSN=SYS1.PROCLIB,DISP=SHR <<===
//SYSUADS DD DSN=SYS1.UADS,DISP=SHR 
//SYSLBC DD DSN=SYS1.BRODCAST,DISP=SHR

JES2

//JES2 PROC 
//IEFPROC EXEC PGM=HASJES20,PARM=NOREQ, 
//DPRTY=(15,15),TIME=1440,PERFORM=9 
//ALTPARM DD DISP=SHR, 
//DSN=SYS1.PARMLIB(JES2BKUP) 
//HASPPARM DD DISP=SHR, 
//DSN=SYS1.PARMLIB(JES2PARM) 
//PROC00 DD DSN=SYS3.PROCLIB,DISP=SHR <<===
//DD DSN=SYS2.PROCLIB,DISP=SHR <<===
//DD DSN=SYS1.PROCLIB,DISP=SHR <<===
//PROC01 DD DSN=SYS4.USERPROC,DISP=SHR 
//DD DSN=SYS3.PROCLIB,DISP=SHR 
//DD DSN=SYS2.PROCLIB,DISP=SHR 
//DD DSN=SYS1.PROCLIB,DISP=SHR 
//IEFRDER DD SYSOUT=* 
//HASPLIST DD DDNAME=IEFRDER

JES2 initialization parameter JOBCLASS PROCLIB entries

JOBCLASS(*) ACCT=NO, /* ACCT # NOT REQUIRED (DEF.)*/ 
…
PROCLIB=01, /* DEFAULT TO //PROC01 DD (DEF.)*/
…
JOBCLASS(STC) AUTH=ALL, /* ALLOW ALL COMMANDS (DEF.)*/ 
…
PROCLIB=00, /* USE //PROC00 DD (DEF.)*/ 
…
JOBCLASS(TSU) AUTH=ALL, /* ALLOW ALL COMMANDS (DEF.)*/
…
PROCLIB=00, /* USE //PROC00 DD (DEF.)*/ 
…

PROCLIB data set that will be used in the access authorization process:

SYS3.PROCLIB
SYS2.PROCLIB 
SYS1.PROCLIB 

The following PROCLIB data set will NOT be used or evaluated:
SYS4.USERPROC

Recommendation for sites:

The following are recommendations for the sites to ensure only PROCLIB data sets that contain the STC and TSO procedures are protected.

- Remove all application PROCLIB data sets from MSTJCLxx and JES2 procedures. The customer will have all JCL changed to use the JCLLIB JCL statement to refer to the application PROCLIB data sets.

Example:
//USERPROC JCLLIB ORDER=(SYS4.USERPROC)

- Remove all access to the application PROCLIB data sets and only authorize system programming personnel WRITE and/or greater access to these data sets.

- Document the application PROCLIB data set access for the customers that require WRITE and/or greater access. Use this documentation as justification for the inappropriate access created by the scripts.

- Change MSTJCLxx and JES2 procedure to identify STC and TSO PROCLIB data sets separate from application PROCLIB data sets. The following is a list of actions that can be performed to accomplish this recommendation:

a. Ensure that MSTJCLxx contains only PROCLIB data sets that contain STC and TSO procedures.
b. If an application PROCLIB data set is required for JES2, ensure that the JES2 procedure specifies more than one PROCxx DD statement concatenation or identified in the JES2 dynamic PROCLIB definitions. Identify one PROCxx DD statement data set concatenation that contains the STC and TSO PROCLIB data sets. Identify one or more additional PROCxx DD statements that can contain any other PROCLIB data sets. The concatenation of the additional PROCxx DD statements can contain the same data sets that are identified in the PROCxx DD statement for STC and TSO. The following is an example of the JES2 procedure:

//JES2 PROC 
//IEFPROC EXEC PGM=HASJES20,PARM=NOREQ, 
//DPRTY=(15,15),TIME=1440,PERFORM=9 
//ALTPARM DD DISP=SHR, 
//DSN=SYS1.PARMLIB(JES2BKUP) 
//HASPPARM DD DISP=SHR, 
//DSN=SYS1.PARMLIB(JES2PARM) 
//PROC00 DD DSN=SYS3.PROCLIB,DISP=SHR 
//DD DSN=SYS2.PROCLIB,DISP=SHR
//DD DSN=SYS1.PROCLIB,DISP=SHR 
//PROC01 DD DSN=SYS4.USERPROC,DISP=SHR 
//DD DSN=SYS3.PROCLIB,DISP=SHR 
//DD DSN=SYS2.PROCLIB,DISP=SHR 
//DD DSN=SYS1.PROCLIB,DISP=SHR 
//IEFRDER DD SYSOUT=* 
//HASPLIST DD DDNAME=IEFRDER

c. Ensure that the JES2 configuration file is changed to specify that the PROCLIB entry for the STC and TSU JOBCLASSes point to the proper PROCxx entry within the JES2 procedure or JES2 dynamic PROCLIB definitions that contain the STC and/or TSO procedures. All other JOBCLASSes can specify a PROCLIB entry that uses the same PROCxx or any other PROCxx DD statement identified in the JES2 procedure or identified in the JES2 dynamic PROCLIB definitions. The following is an example of the JES2 initialization parameters:

JOBCLASS(*) ACCT=NO, /* ACCT # NOT REQUIRED (DEF.)*/ 
…
PROCLIB=01, /* DEFAULT TO //PROC01 DD (DEF.)*/
…
JOBCLASS(STC) AUTH=ALL, /* ALLOW ALL COMMANDS (DEF.)*/ 
…
PROCLIB=00, /* USE //PROC00 DD (DEF.)*/ 
…
JOBCLASS(TSU) AUTH=ALL, /* ALLOW ALL COMMANDS (DEF.)*/
…
PROCLIB=00, /* USE //PROC00 DD (DEF.)*/ 
…

d. Ensure that only system programming personnel are authorized WRITE and/or greater access to PROCLIB data sets that contain STC and TSO procedures.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25360r514749_chk'
  tag severity: 'high'
  tag gid: 'V-223687'
  tag rid: 'SV-223687r604139_rule'
  tag stig_id: 'RACF-ES-000390'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25348r514750_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98079', 'SV-107183']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
