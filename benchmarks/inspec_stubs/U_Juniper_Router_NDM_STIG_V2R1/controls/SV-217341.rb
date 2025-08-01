control 'SV-217341' do
  title 'The Juniper router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement.

system {
…
…
…
    }
    services {
        ssh {
            protocol-version v2;
            ciphers aes128-cbc;
        }
    }

If the router is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the router to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm as shown in the example below.

[edit system services]
set ssh ciphers aes128-cbc'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18568r296601_chk'
  tag severity: 'high'
  tag gid: 'V-217341'
  tag rid: 'SV-217341r400159_rule'
  tag stig_id: 'JUNI-ND-001200'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-18566r296602_fix'
  tag 'documentable'
  tag legacy: ['SV-101271', 'V-91171']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
