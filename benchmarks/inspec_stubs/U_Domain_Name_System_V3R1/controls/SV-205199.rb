control 'SV-205199' do
  title 'In the event of an error when validating the binding of another DNS servers identity to the DNS information, the DNS server implementation must log the event and send notification to the DNS administrator.'
  desc "Failing to act on the validation errors may result in the use of invalid, corrupted, or compromised information. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

At a minimum, the application must log the validation error. However, more stringent actions can be taken based on the security posture and value of the information. The organization should consider the system's environment and impact of the errors when defining the actions. Additional examples of actions include automated notification to administrators, halting system process, or halting the specific operation.

The DNS server should audit all failed attempts at server authentication through DNSSEC and TSIG/SIG(0). The actual auditing is performed by the OS/NDM but the configuration to trigger the auditing is controlled by the DNS server."
  desc 'check', "Review the DNS server implementation configuration to determine if the DNS server, when it encounters an event or an error when validating the binding of another DNS server's identity to the DNS information, is configured to log the event and send notification to the DNS administrator.

If the DNS server does not log the event and send notification to the DNS administrator in the event of such a validation error, this is a finding."
  desc 'fix', "Configure the DNS server to log the event and send notification to the DNS administrator in the event an error occurs when validating the binding of another DNS server's identity to the DNS information."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5466r392510_chk'
  tag severity: 'medium'
  tag gid: 'V-205199'
  tag rid: 'SV-205199r879727_rule'
  tag stig_id: 'SRG-APP-000350-DNS-000044'
  tag gtitle: 'SRG-APP-000350'
  tag fix_id: 'F-5466r392511_fix'
  tag 'documentable'
  tag legacy: ['SV-69223', 'V-54977']
  tag cci: ['CCI-000366', 'CCI-001906']
  tag nist: ['CM-6 b', 'AU-10 (2) (b)']
end
