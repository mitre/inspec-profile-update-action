control 'SV-213715' do
  title 'DB2 must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Run the following query to check the existing thresholds defined in database: 
DB2> SELECT thresholdname, thresholdpredicate, maxvalue, execution 
           FROM syscat.thresholds

If there are no thresholds defined in the required categories this is a finding. 

Review the defined thresholds, if the thresholds are not defined per the organization policies, this is a finding. 

Note: Select the following link for the knowledgebase on syscat.thresholds: 

http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0050565.html?cp=SSEPGG_10.5.0%2F2-12-8-111'
  desc 'fix', 'Run the CREATE THRESHOLD statement to create the thresholds per organization policies. 

The following command is an example for creating a threshold to terminate any sessions which have been inactive for more than 5 hours: 
DB2>  CREATE THRESHOLD MONIDLETIME FOR DATABASE ACTIVITIES ENFORCEMENT DATABASE 
     WHEN CONNECTIONIDLETIME > 300 MINUTE STOP EXECUTION 

Note: Select the following link for the knowledgebase information on create threshold: 

http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0050563.html?lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14936r295194_chk'
  tag severity: 'medium'
  tag gid: 'V-213715'
  tag rid: 'SV-213715r879673_rule'
  tag stig_id: 'DB2X-00-006400'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-14934r295195_fix'
  tag 'documentable'
  tag legacy: ['SV-89193', 'V-74519']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
