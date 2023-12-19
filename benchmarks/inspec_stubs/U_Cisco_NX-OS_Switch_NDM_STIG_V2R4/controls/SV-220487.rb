control 'SV-220487' do
  title 'The Cisco switch must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record.
An alternative to using a sealed envelope in a safe would be credential files, separated by technology, located in a secured location on a file server, with the files only accessible to those administrators authorized to use the accounts of last resort, and access to that location monitored by a central log server. 
Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Step 1: Review the Cisco switch configuration to verify that a local account for last resort has been configured with a privilege level that will enable the administrator to troubleshoot connectivity to the authentication server.

username xxxxxxxxxxxxx password 5 $5$88SPgpAn$Q6/17o5U/5lz4dNL1iQZuj/1a0wcKdrk29ZH1HJsnF. role priv-9

Step 2: Verify that the fallback to use local account has not been disabled as shown in the example below:

no aaa authentication login default fallback error local

Note: The fallback is enabled by default; hence the above command should not be seen in the configuration.

If the Cisco switch is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'Step 1: Configure a local account with the necessary privilege level to troubleshoot network outage and restore operations as shown in the following example: 

SW2(config)# switch(config)# username xxxxxxx password xxxxxx role priv-9

Step 2: Configure the authentication to use an AAA server with the fallback to use the local account if the authentication server is not reachable as shown in the following example:

SW2(config)# aaa authentication login default group RADIUS_SERVERS
SW2(config)# aaa authentication login default fallback error local
SW2(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22202r539182_chk'
  tag severity: 'medium'
  tag gid: 'V-220487'
  tag rid: 'SV-220487r879589_rule'
  tag stig_id: 'CISC-ND-000490'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-22191r539183_fix'
  tag 'documentable'
  tag legacy: ['SV-110623', 'V-101519']
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
