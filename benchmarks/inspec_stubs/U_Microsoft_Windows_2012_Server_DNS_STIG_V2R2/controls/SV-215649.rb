control 'SV-215649' do
  title 'The Windows 2012 DNS Server must, in the event of an error validating another DNS servers identity, send notification to the DNS administrator.'
  desc "Failing to act on the validation errors may result in the use of invalid, corrupted, or compromised information. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

At a minimum, the application must log the validation error. However, more stringent actions can be taken based on the security posture and value of the information. The organization should consider the system's environment and impact of the errors when defining the actions. Additional examples of actions include automated notification to administrators, halting system process, or halting the specific operation.

The DNS server should audit all failed attempts at server authentication through DNSSEC and TSIG/SIG(0). The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server."
  desc 'check', 'Windows 2012 DNS servers, hosting Active Directory integrated zones, transfer zone information via AD replication. Windows 2012 DNS servers hosting non-AD-integrated zones as a secondary name server and/or are not hosting AD-integrated zones use zone transfer to sync zone data.

If the Windows 2012 DNS server only hosts AD-integrated zones and all other name servers for the zones hosted are Active Directory Domain Controllers, this requirement is not applicable.

If the Windows 2012 DNS server is not an Active Directory Domain Controller, or is a secondary name server for a zone with a non-AD-integrated name server as the master, this requirement is applicable.

Administrator notification is only possible if a third-party event monitoring system is configured or, at a minimum, there are documented procedures requiring the administrator to review the DNS logs on a routine, daily basis.

If a third-party event monitoring system is not configured, or a document procedure is not in place requiring the administrator to review the DNS logs on a routine, daily basis, this is a finding.'
  desc 'fix', 'To detect and notify the administrator, configure a third-party event monitoring system or, at a minimum, document and implement a procedure to require the administrator to check the DNS logs on a routine, daily basis.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16843r314422_chk'
  tag severity: 'medium'
  tag gid: 'V-215649'
  tag rid: 'SV-215649r561297_rule'
  tag stig_id: 'WDNS-AU-000003'
  tag gtitle: 'SRG-APP-000350-DNS-000044'
  tag fix_id: 'F-16841r314423_fix'
  tag 'documentable'
  tag legacy: ['SV-72977', 'V-58547']
  tag cci: ['CCI-001906', 'CCI-000366']
  tag nist: ['AU-10 (2) (b)', 'CM-6 b']
end
