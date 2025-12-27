control 'SV-24890' do
  title 'The Oracle INBOUND_CONNECT_TIMEOUT and SQLNET.INBOUND_CONNECT_TIMEOUT parameters should be set to a value greater than 0.'
  desc 'The INBOUND_CONNECT_TIMEOUT_[listener-name] and SQLNET.INBOUND_CONNECT_TIMEOUT defines the limit the database listener and database server respectively will wait for a client connection to complete after a connection request is made. This limit protects the listener and database server from a Denial-of-Service attack where multiple connection requests are made that are not used or closed from a client. Server resources can be exhausted if unused connections are maintained.'
  desc 'check', 'Review the listener.ora file and the sqlnet.ora file.

If the INBOUND_CONNECT_TIMEOUT_[listener-name] parameter does not exist for each listener found in the listener.ora and contain a value greater than 0, this is a Finding.

If the SQLNET.INBOUND_CONNECT_TIMEOUT parameter does not exist in the sqlnet.ora and contain a value greater than 0, this is a Finding.

NOTE: although the default value may provide adequate protection, assuming the default could lead to unanticipated changes in future product updates. Specify a value to manage the setting.'
  desc 'fix', "Using a text editor or administrative tool, modify the listener.ora file to include a limit for connection request timeouts for the listener.

Example entry (value unit is in seconds):

  INBOUND_CONNECT_TIMEOUT_LISTENER = 2

Modify the sqlnet.ora file to include a limit for connection request timeouts for the listener.

Example entry (value unit is in seconds):

  SQLNET.INBOUND_CONNECT_TIMEOUT = 3

Review the Oracle Net Services Administrator's Guide for information about configuring these parameters."
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29443r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3862'
  tag rid: 'SV-24890r1_rule'
  tag stig_id: 'DO0286-ORACLE11'
  tag gtitle: 'Oracle connection timeout parameter'
  tag fix_id: 'F-26505r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
