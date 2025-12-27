control 'SV-251595' do
  title 'IDMS must protect against the use of external request exits that change the userid to a shared id when actions are performed that may be audited.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account.

User exits that change userids can be used to hide the true identities of those who may perform an action and should be carefully restricted or eliminated."
  desc 'check', 'Log in to the CV and enter command DCPROFIL. Press "Enter" until the page titled "Named User Exits" appears. Find the entry for USRIDXIT. 

If the DEFINED column says YES, then a user-written exit has been linked with IDMSUXIT. 

If a user-written exit USRIDXIT has been linked with IDMSUXIT (for batch or TSO-front end use), UCFCICS (UCF access from a CICS transaction) or IDMSINTC (DML or SQL access form a CICS transaction server front-end) and the USRIDXIT changes the userid to a shared userid, this is a finding.'
  desc 'fix', 'Remove code from USRIDXIT that changes the individual userid to a shared user or remove the exit entirely.

After making the above changes, assemble and link IDMSUXIT. To implement the new IDMSUXIT either recycle any CVs that use it or issue these commands:

DCMT VARY NUCLEUS MODULE IDMSUXIT NEW COPY
DCMT VARY NUCLEUS RELOAD'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55030r807650_chk'
  tag severity: 'low'
  tag gid: 'V-251595'
  tag rid: 'SV-251595r808360_rule'
  tag stig_id: 'IDMS-DB-000150'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-54984r808359_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
