control 'SV-24893' do
  title 'The Oracle SQLNET.EXPIRE_TIME parameter should be set to a value greater than 0.'
  desc 'The SQLNET.EXPIRE_TIME parameter defines a limit for the frequency of active connection verification of a client connection. This prevents indefinite open connections to the database where client connections have not been terminated properly. Indefinite open connections could lead to an exhaustion of system resources or leave an open connection available for compromise.'
  desc 'check', 'View the SQLNET.ORA file to verify if a SQLNET.EXPIRE_TIME has been set to the value greater than 0.

If the parameter does not exist or is set to 0, this is a Finding.'
  desc 'fix', 'Using a text editor or administrative tool, modify the SQLNET.ORA file on the database host server to include a limit for connection request timeouts for the listener.

Example entry (value unit is in minutes):

  SQLNET.EXPIRE_TIME = 3

NOTE: Use the lowest number possible that does not generate so much network traffic that performance becomes unacceptable. The lower the number, the less likely an exhaustion of resources will occur. Set the value to the lowest number greater than 0 that is supported by the target system environment.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29445r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3863'
  tag rid: 'SV-24893r1_rule'
  tag stig_id: 'DO0287-ORACLE11'
  tag gtitle: 'Oracle SQLNET.EXPIRE_TIME parameter'
  tag fix_id: 'F-26508r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
