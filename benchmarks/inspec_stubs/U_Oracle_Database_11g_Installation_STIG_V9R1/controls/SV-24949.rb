control 'SV-24949' do
  title 'The Oracle Listener ADMIN_RESTRICTIONS parameter if present should be set to ON.'
  desc 'The Oracle listener process can be dynamically configured. By connecting to the listener process directly, usually through the Oracle LSNRCTL utility, a user may change any of the parameters available through the set command. This vulnerability has been used to overwrite the listener log and trace files. The ADMIN_RESTRICTIONS parameter, set in the listener.ora file, prohibits dynamic listener configuration changes and protects the configuration using host operating system security controls.'
  desc 'check', 'If a listener is not running on the local database host server, this check is Not a Finding.

Use the LSNRCTL utility and issue the STATUS [listener-name] command to locate the listener.ora file.

Open the listener.ora file in a text editor or viewer.

Locate the line with ADMIN_RESTRICTIONS_[listener-name] = ON where listener-name is the alias of the listener supplied by the DBA.

If no such line is found, this is a Finding.

Repeat for each listener listed in the LISTENER.ORA file.'
  desc 'fix', 'Edit the listener.ora file and add the following line for each listener in use on the system:

ADMIN_RESTRICTIONS_[listener-name] = ON

Restart the listener to activate the setting.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29489r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3497'
  tag rid: 'SV-24949r1_rule'
  tag stig_id: 'DO6740-ORACLE11'
  tag gtitle: 'Oracle listener ADMIN_RESTRICTIONS parameter'
  tag fix_id: 'F-26557r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
