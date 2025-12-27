control 'SV-251596' do
  title 'IDMS must protect against the use of numbered exits that change the userid to a shared id.'
  desc "Non-repudiation of actions taken is required to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account.

User exits that change userids can be used to hide the true identities of those who may perform an action and should be carefully restricted or eliminated."
  desc 'check', "Issue LOOK PROGRAM=RHDCUXIT. If there are non-zeros in the 12 bytes starting at X'200', exit 27 is being used. 

If there are non-zeros in the 12 bytes starting at X'20C', exit 28 is being used. 

Check exits for a change in userid and if there is a change to a shared user ID, this is a finding."
  desc 'fix', 'Remove code from exit 27 and/or exit 28 that changes the individual user id to a shared user or remove the exit entirely, then reassemble and relink RHDCUXIT.

To implement the new RHDCUXIT, either recycle any CVs that use the SRTT or issue these commands:
 
DCMT VARY NUCLEUS MODULE RHDCUXIT NEW COPY
DCMT VARY NUCLEUS RELOAD'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55031r807653_chk'
  tag severity: 'low'
  tag gid: 'V-251596'
  tag rid: 'SV-251596r807655_rule'
  tag stig_id: 'IDMS-DB-000160'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-54985r807654_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
