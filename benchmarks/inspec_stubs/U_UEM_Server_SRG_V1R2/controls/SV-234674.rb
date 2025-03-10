control 'SV-234674' do
  title 'If cipher suites using pre-shared keys are used for device authentication, the UEM server must have a minimum security strength of 112 bits or higher.'
  desc 'Pre-shared keys are symmetric keys that are already in place prior to the initiation of a Transport Layer Security (TLS) session (e.g., as the result of a manual distribution). In general, pre-shared keys should not be used. However, the use of pre-shared keys may be appropriate for some closed environments that have stung key management best practices. 

Pre-shared keys may be appropriate for constrained environments with limited processing, memory, or power. If pre-shared keys are appropriate and supported, the following additional guidelines must be followed. Consult 800-52 for recommended pre-shared key cipher suites for pre-shared keys. Pre-shared keys must be distributed in a secure manner, such as a secure manual distribution or using a key establishment certificate. These cipher suites employ a pre-shared key for device authentication (for both the server and the client) and may also use RSA or ephemeral Diffie-Hellman (DHE) algorithms for key establishment. 

Because these cipher suites require pre-shared keys, these suites are not generally applicable to classic secure website applications and are not expected to be widely supported in TLS clients or TLS servers. NIST suggests that these suites be considered in particular for infrastructure applications, particularly if frequent authentication of the network entities is required. These cipher suites may be used with TLS versions 1.1 or 1.2. Note that cipher suites using GCM, SHA-256, or SHA-384 are only available in TLS 1.2.'
  desc 'check', 'Verify cipher suites using pre-shared keys are for device authentication have a minimum security strength of 112 bits or higher.

If cipher suites using pre-shared keys are for device authentication do not have a minimum security strength of 112 bits or higher, this is a finding.'
  desc 'fix', 'If cipher suites using pre-shared keys are used for device authentication, configure the UEM server to have a minimum security strength of 112 bits or higher.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37859r851731_chk'
  tag severity: 'medium'
  tag gid: 'V-234674'
  tag rid: 'SV-234674r879894_rule'
  tag stig_id: 'SRG-APP-000585-UEM-000399'
  tag gtitle: 'SRG-APP-000585'
  tag fix_id: 'F-37824r615657_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
