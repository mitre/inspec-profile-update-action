control 'SV-251636' do
  title 'IDMS must prevent users without the appropriate access from executing privileged functions or tasks within the IDMS environment.'
  desc 'In general, all functions within IDMS can be controlled, therefore it is up to the IDMS system administrator to determine which functions or tasks are secured or require proper authorization. Any function within the IDMS environment can be considered privileged if the administrator deems it appropriate. Access to different functions is protected through a number of load modules that are generated from assembler macros. The load modules are RHDCSRTT, IDMSCTAB, and IDMSUTAB. The related assembler macros are #SECRTT, #CTABGEN, and #UTABGEN. The #SECRTT macro is used to define different functions to the ESM so that they can be secured. The #UTABGEN macro is used to secure specific OCF/BCF commands. The #CTABGEN macro is used to secure DCMT commands. 

IDMS provides several tasks, programs and data sets that, in the wrong hands, could allow access to sensitive data or give access to make detrimental changes. These tasks, programs and data sets should be deemed privileged and protected from unauthorized users.'
  desc 'check', 'The following steps apply to "Online" and "Batch to CV" access to IDMS.

If CAGJMAC and AAGJMAC libraries with external security manager (ESM) dataset level security are not secured, this is a finding. 

If the functions to be protected within the RHDCSRTT, IDMSCTAB, or IDMSUTAB modules are not defined, this is a finding.

Note: The recommended method of securing the IDMS environment is through the ESM. The RHDCSRTT module allows users to define the different functions and applications as type EXTERNAL to make them visible to the ESM so that they can be secured. These load modules are used by the IDMS Central Version to understand how access to the IDMS environment is to be controlled. Again, it is not sufficient to merely define what should be secured via the RHDCSRTT module, these functions must be secured through the ESM. 

The security of the assembler macros and the security load modules must be upheld to protect the environment. Use the ESM to enact Dataset Level Security on the CAGJMAC macro library where the IDMS assembler macros reside. This is to protect unauthorized users from creating their own versions of the security load modules. Also, protect the CUSTLOAD load library or wherever the generated security load modules used by the IDMS environment are stored. 

By defining the functions to be protected in the RHDCSRTT module and then protecting those functions via the ESM, users are able to protect the DBMS environment. By taking these steps, unauthorized users are prevented from performing privileged functions when executing jobs in either a "Batch to Central Version" or "Online Central Version" environment. 

If accessing CA IDMS in "Batch Local" mode, access control is performed at the dataset level using the ESM. It is necessary to restrict users from accessing the CA IDMS Database files in Local Mode. If the CA IDMS Database files are not secured using the ESM, this is a finding.

If limited access is allowed to database files in a batch to local scenario, consider utilizing a custom EXIT 14.

If a user wishes to granularly protect specific DBMS verbs and have not implemented an EXIT 14, this is a finding.'
  desc 'fix', "1. Define the functions to secure using the #SECRTT, #CTABGEN, and #UTABGEN macros. See the IDMS documentation for information on how use these macros to secure the CA IDMS environment. 

2. Protect the IDMS macro libraries with the ESM's dataset level security (see the ESM's documentation to restrict access except for the administrators).

3. Protect the IDMS custom load library containing the RHDCUXIT, RHDCSRTT, IDMSCTAB, or IDMSUTAB modules. See the ESM's documentation to restrict access except for the IDMS Central Version, administrators, and any other users who require access.

4. If access must be restricted to the CA IDMS Database files in Local Mode, and the CA IDMS Database files are not properly secured using an ESM, then do so. All pertinent CA IDMS software load libraries and customization load libraries should also be secured. Only allow access to these files by the IDMS Central Version or specific administrator IDs as specified by the ESM. This protects the system from unauthorized users utilizing alternative load libraries or security settings to access database files, and also prevents them from directly accessing the database files.

5. If granularly controlling user access in batch to local mode is required and EXIT 14 is not set up in the RHDCUXIT module, see the IDMS documentation. Use EXIT 14 to decide which database verbs to protect. Access is protected by associating the verbs with a security resource in the RHDCSRTT, which is protected by the ESM. This is an exit that must be compiled into the RHDCUXIT load module. This exit is called at the time of a database verb being called and allows users to define which verbs are secured and how they are secured by issued Security Checks based on the user making the calls. This allows a user to choose which verbs are privileged and who is able to access them. As before, the verbs are secured by associating them with a defined access type in the RHDCSRTT, module which then needs to be secured by the ESM. By using the ESM's dataset level security and Exit 14, access is restricted to functions that should be protected."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55071r807773_chk'
  tag severity: 'medium'
  tag gid: 'V-251636'
  tag rid: 'SV-251636r855274_rule'
  tag stig_id: 'IDMS-DB-000650'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-55025r807774_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
