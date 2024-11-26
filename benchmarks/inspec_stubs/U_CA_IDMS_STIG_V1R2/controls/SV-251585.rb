control 'SV-251585' do
  title 'IDMS must enforce applicable access control policies, even after a user successfully signs on to CV.'
  desc 'Unless the DBMS is secured properly, there are innumerable ways that a system and its data can be compromised. The IDMS SRTT is the basis for mitigating these problems.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

In the SRTT, resources are protected by #SECRTT TYPE=ENTRY and TYPE=OCCURRENCE statements.

Examine the SRTT to ensure that there are #SECRTT statements for the desired recourses that have "SECBY=EXTERNAL". If there are none, this is a finding.'
  desc 'fix', "Secure the desired resources by updating RHDCSRTT adding #SECRTT TYPE=ENTRY and TYPE=OCCURRENCE statements as needed. For example:

          #SECRTT TYPE=ENTRY,                                           X
                    RESTYPE=resource,                                     X
                   SECBY=EXTERNAL,                                         X
                   EXTCLS='CA@IDMS',                                  X
                   EXTNAME=(your_extname)                                    

Before implementing changes, contact the security administrator and ensure that the external security manager (ESM) has the necessary rules for the EXTCLS and EXTNAME values that were chosen. These rules must then be given to the appropriate users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(your_extname)

After making the above changes assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:       
 
DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD"
  impact 0.7
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55020r807620_chk'
  tag severity: 'high'
  tag gid: 'V-251585'
  tag rid: 'SV-251585r807622_rule'
  tag stig_id: 'IDMS-DB-000040'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54974r807621_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
