control 'SV-216530' do
  title 'The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record.
An alternative to using a sealed envelope in a safe would be credential files, separated by technology, located in a secured location on a file server, with the files only accessible to those administrators authorized to use the accounts of last resort, and access to that location monitored by a central log server. 
Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Step 1: Review the Cisco router configuration to verify that a local account for last resort has been configured.

username xxxxxxxxxxxx
 group netadmin
 secret 5 xxxxxxxxxxxxxxxxxxxx

Note: The following groups should not be assigned to this local account: root-system and root-lr. A custom group that provides appropriate tasks can be used.

Step 2: Verify that local is defined after radius or tacas+ in the authentication order as shown in the example below.

aaa authentication login default group tacacs+ local

If the Cisco router is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'Step 1: Configure a local account with the necessary privilege level to troubleshoot network outage and restore operations as shown in the following example: 

RP/0/0/CPU0:R3(config)#username xxxxxxxxx group netadmin 
RP/0/0/CPU0:R3(config)#username xxxxxxxxx secret xxxxxx

Step 2: Configure the authentication order to use the local account if the authentication server is not reachable as shown in the following example:

RP/0/0/CPU0:R3(config)#aaa authentication login default group tacacs+ local'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17765r288276_chk'
  tag severity: 'medium'
  tag gid: 'V-216530'
  tag rid: 'SV-216530r879589_rule'
  tag stig_id: 'CISC-ND-000490'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-17762r288277_fix'
  tag 'documentable'
  tag legacy: ['SV-105545', 'V-96407']
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
