control 'SV-251594' do
  title 'IDMS must protect against the use of default userids.'
  desc 'Default sign-ons can be used by individuals to perform adverse actions anonymously.'
  desc 'check', 'Examine load module "RHDCSRTT" by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476. 

If the TYPE=INITIAL #SECRTT has DFLTSGN=YES specified, this is a finding.

If DFLTUID is defined, this is a finding.'
  desc 'fix', 'Set DFLTSGN=NO and remove the DFLTUID from the #SECRTT INITIAL macro that is input to the RHDCSRTT module, then reassemble and relink RHDCSRTT.

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:       
 
DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55029r807647_chk'
  tag severity: 'low'
  tag gid: 'V-251594'
  tag rid: 'SV-251594r807649_rule'
  tag stig_id: 'IDMS-DB-000140'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-54983r807648_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
