control 'SV-252141' do
  title 'MongoDB must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Systems that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state data also facilitates system restart and return to the operational mode of the organization with less disruption of mission/business processes.

Databases must fail to a known consistent state. Transactions must be successfully completed or rolled back.

In general, security mechanisms should be designed so that a failure will follow the same execution path as disallowing the operation. For example, application security methods, such as isAuthorized(), isAuthenticated(), and validate(), should all return false if there is an exception during processing. If security controls can throw exceptions, they must be very clear about exactly what that condition means.

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.

'
  desc 'check', 'Journaling is enabled by default.

With journaling enabled, if mongod stops unexpectedly, the program can recover everything written to the journal. 

MongoDB will re-apply the write operations on restart and maintain a consistent state.
 
To validate the mongod configuration, run the following command:

 db.getSiblingDB("admin").runCommand({getCmdLineOpts: 1}).parsed.storage.journal
   
If it returns { enabled : false } or no output, this is a finding.'
  desc 'fix', 'Modify the mongod startup command-line options by removing the --nojournal option.

Edit the MongoDB database configuration file (default location: /etc/mongod.conf) to ensure the option storage.journal.enabled is present and set to true as show below:

    storage:
       journal:
          enabled: true

Stop/start (restart) any or all mongod or mongos processes.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55597r813803_chk'
  tag severity: 'medium'
  tag gid: 'V-252141'
  tag rid: 'SV-252141r813805_rule'
  tag stig_id: 'MD4X-00-000800'
  tag gtitle: 'SRG-APP-000225-DB-000153'
  tag fix_id: 'F-55547r813804_fix'
  tag satisfies: ['SRG-APP-000225-DB-000153', 'SRG-APP-000226-DB-000147']
  tag 'documentable'
  tag cci: ['CCI-001190', 'CCI-001665']
  tag nist: ['SC-24', 'SC-24']
end
