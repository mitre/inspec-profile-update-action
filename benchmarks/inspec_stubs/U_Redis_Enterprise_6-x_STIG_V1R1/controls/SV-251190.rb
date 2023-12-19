control 'SV-251190' do
  title 'Redis Enterprise DBMS must provide audit record generation capability for DoD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful login attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logins from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', 'Review the organization documentation to determine the organization-defined auditable events.

To validate the log of an event, check the logs tab for configuration actions within Redis Enterprise.
 
On the Redis Enterprise UI:
1. Log in to Redis Enterprise.
2. Navigate to the logs page.
3. Review the logs as needed to verify they meet organizationally defined audit events.

On the underlying server, logs may also be found in /var/opt/redislabs/log/<log_name>

The eventlog.log and cnm_http log files contain all logs.

To check, perform an event that should trigger an organizationally defined audit log.

Review logs in the UI, and in /var/opt/redislabs/log/eventlog.log and /var/opt/redislabs/log/cnm_http.log for applicable event logs.

Check DBMS auditing to determine whether organization-defined auditable events are being audited by the system.

To check the current verbosity (log level), run the following command from the underlying node (as root):

ccs-cli hget dmc:<node_id> log_level and ccs-cli hget dmc:<node_id> mgmt_log_level

If the field does not exist it means the DMC is working with its default log_level which is "info".

If the action is not captured in the logs page audit trail, this is a finding.'
  desc 'fix', "Logging verbosity on Redis Enterprise can be changed for error messages and debugging purposes. Auditing and logging levels for user actions on the control plane does not change and cannot be configured.

Configure the verbosity to the organizationally defined level:

1. Enter the relevant node and run the following commands (run on each desired node): 
- ccs-cli hset dmc:<node_id> log_level <log_level>
- ccs-cli hset dmc:<node_id> mgmt_log_level <log_level>

2. Reconfigure the DMC: 
rlutil dmc_reconf dmc=<node_id>

3. Set a specific log level in the DMC for a given DB:
- ccs-cli hset bdb:<db_id> log_level <log_level> 
- rlutil dmc_reconf bdb=<db_id> 

Logging levels include:
1. Debug (DBG) - at this level, anything goes, to include whatever a developer finds useful for debugging. This level should very rarely be active in production and is intended for developers only.

2. Trace (TRC) - used for tracking specific elements' lifespan, issues a few messages (only those important for tracing element) per flow. It might be used in production, under very restrictive and careful watch, for very short periods of time.

3. Info (INF) - positive events changing the behavior of app or one of its major elements: a key component started, configuration changed, etc.

4. Warn (WRN) - events that have temporary (usually recoverable) negative impact on one or more major application elements (server went down, a temporary lack or resources, etc.), such events lead to undesired impact on many sub-elements, while others can still function properly.

5. Error (ERR) - unexpected, harmful events - a key element/component cannot function properly, there is no way to recover proper functionality until this situation is resolved (configuration in accessible, or fundamentally broken, network unreachable, etc.).

6. Fatal (FTL) - unrecoverable state. Usually, the last message (or one of very few of them) in an app's lifetime.

NOTICE: Level info (3) and above are enabled by default."
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54625r804758_chk'
  tag severity: 'medium'
  tag gid: 'V-251190'
  tag rid: 'SV-251190r804760_rule'
  tag stig_id: 'RD6X-00-001400'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-54579r804759_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
