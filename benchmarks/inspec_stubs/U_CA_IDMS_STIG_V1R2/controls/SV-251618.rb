control 'SV-251618' do
  title 'IDMS must prevent unauthorized and unintended information transfer via database buffers.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.'
  desc 'check', 'Log on to IDMS DC system and issue "DCPROFIL".

If PRIMARY STORAGE PROTECT KEY is the same as the ALTERNATE STORAGE KEY, this is a finding.

If SYSTEM STORAGE PROTECTED is "NO", this is a finding.

Issue command "DCMT DISP PROG xxxxxxxx" and "DCMT DISP DYN PROG xxxxxxxx" replacing [xxxxxxxx] with the names of user programs and look for Storage Prot. If any are "NO", then this is a finding.

Issue command "DCMT DISP BUFFER". If any of the buffers do not have OPSYS in the Getstg column, this is a finding.'
  desc 'fix', %q(Do the following to place buffers into storage acquired from the operating system rather than from IDMS. Use the following system generation parameters to enable the use of OPSYS storage for the buffers: 
Set STORAGE KEY parameter of the SYSGEN SYSTEM statement to a value different from the ALTERNATE STORAGE KEY.

Set PROTECT/NOPROTECT parameter of the SYSGEN SYSTEM statement to PROTECT.

Set PROTECT/NOPROTECT parameter of the SYSGEN PROGRAM statement to PROTECT for user programs.

Using the #CTABGEN macro, secure DCMT commands:
- VARY BUFFER (code N010)
- VARY DYNAMIC PROGRAM (code N046001)
- VARY PROGRAM (code N025)
Here is an example where all three commands are assigned task code 3:
         #CTABGEN (A,3),                                               X
               (N010,A,N025,N046001,A)
Using the above example, and assuming the SYSTEM ID of this IDMS system specified in SYSGEN is TEST001 the SRTT entry could be:

#SECRTT TYPE=ENTRY,RESTYPE=ACTI,       -
        SECBY=EXTERNAL,                                     -
        EXTCLS='CA@IDMS',                                 -
        EXTNAME=(SYST,ACTI)             

The DCMT commands could be assigned to users in Top Secret:
TSS PER(user_id) CA@IDMS(TEST001.DCMT003) ACCESS(READ)

Reassemble the SRTT and/or module IDMSCTAB and issue commands:
DCMT VARY NUC MODULE IDMSCTAB NEW COPY -for IDMSCTAB
DCMT VARY NUC MODULE RHDCSRTT NEW COPY - for RHDCSRTT
then for either or both:
DCMT VARY NUCLEUS RELOAD 

To set buffers to OPSYS storage:
Access OCF or BCF and connect to the applicable dictionary.

Enter "DISPLAY BUFFER nnnnnnnn AS SYNTAX VERB ALTER" where [nnnnnnnn] is the name of the buffer.

Change the DC STORAGE parameter to "OPSYS STORAGE".

After changing all needed buffers, GENERATE the DMCL.

Punch and link the DMCL module. 

Cycle the CV or issue "DCMT VARY DMCL NEW COPY".

Note: If specifying OPSYS storage for buffers, IDMS will attempt to allocate the buffer storage in operating system storage rather than in IDMS storage. Should the allocation attempt fail, IDMS will attempt to allocate the buffer in IDMS storage, and messages DC205032 and DC205029 will be issued indicating this.)
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55053r807719_chk'
  tag severity: 'medium'
  tag gid: 'V-251618'
  tag rid: 'SV-251618r807721_rule'
  tag stig_id: 'IDMS-DB-000470'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-55007r807720_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
