control 'SV-233892' do
  title 'The Infoblox system must send a notification in the event of an error when validating the binding of another DNS server’s identity to the DNS information.'
  desc "Failing to act on validation errors may result in the use of invalid, corrupted, or compromised information. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

At a minimum, the application must log the validation error. However, more stringent actions can be taken based on the security posture and value of the information. The organization should consider the system's environment and impact of the errors when defining the actions. Additional examples of actions include automated notification to administrators, halting system process, or halting the specific operation.

The DNS server should audit all failed attempts at server authentication through DNSSEC and TSIG/SIG(0). The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server."
  desc 'check', 'Infoblox systems allow configuration of DNS auditing based on selectable events. Verify that important event categories are enabled to log events. 

1. Navigate to Data Management >> DNS and select "Grid DNS Properties". 
2. Toggle Advanced Mode and review the "Logging" tab.  
3. Validate that at a minimum the following categories are enabled:
client
config
database
dnssec
lame servers
network
notify
rate-limit
resolver
security
transfer-in
transfer-out
update
update-security
4. When complete, click "Cancel" to exit the "Properties" screen.   

If the named logging categories are not enabled, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS. Select "Grid DNS Properties".
2. Toggle Advanced Mode and review the "Logging" tab.  
3. Enable the following categories using the check boxes: 
client
config
database
dnssec
lame servers
network
notify
rate-limit
resolver
security
transfer-in
transfer-out
update
update-security
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
5. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37077r611196_chk'
  tag severity: 'medium'
  tag gid: 'V-233892'
  tag rid: 'SV-233892r621666_rule'
  tag stig_id: 'IDNS-8X-400034'
  tag gtitle: 'SRG-APP-000350-DNS-000044'
  tag fix_id: 'F-37042r611197_fix'
  tag 'documentable'
  tag cci: ['CCI-001906', 'CCI-000366']
  tag nist: ['AU-10 (2) (b)', 'CM-6 b']
end
