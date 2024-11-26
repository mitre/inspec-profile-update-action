control 'SV-215679' do
  title 'The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record.

An alternative to using a sealed envelope in a safe would be credential files, separated by technology, located in a secured location on a file server, with the files only accessible to those administrators authorized to use the accounts of last resort, and access to that location monitored by a central log server. 

Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Step 1: Review the router configuration to verify that a local account for last resort has been configured with a privilege level that will enable the administrator to troubleshoot connectivity to the authentication server.

username xxxxxxxxxxx privilege 10 common-criteria-policy PASSWORD_POLICY password xxxxxxxxxx

Note: The configured Common Criteria policy must be used when creating or changing the local account password as shown in the example above.

Step 2: Verify that local is defined after radius or tacacs+ in the authentication order as shown in the example below:

aaa authentication login default group tacacs+ local

If the router is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'Step 1: Configure a local account as shown in the example below.

R2(config)#username xxxxxxxxx privilege nn secret xxxxxxx

Step 2: Configure the authentication order to use the local account if the authentication server is not reachable as shown in the following example:

R2(config)#aaa authentication login default group tacacs+ local'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16873r508014_chk'
  tag severity: 'medium'
  tag gid: 'V-215679'
  tag rid: 'SV-215679r879589_rule'
  tag stig_id: 'CISC-ND-000490'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-16871r508015_fix'
  tag 'documentable'
  tag legacy: ['SV-105199', 'V-96061']
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
